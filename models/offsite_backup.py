import glob
import gzip
import hashlib
import json
import logging
import os
import platform
import re
import shutil
import subprocess
import tempfile
import urllib.request
import zipfile
from datetime import datetime, timezone

from odoo import api, models, tools
from odoo.exceptions import UserError
from odoo.tools.misc import exec_pg_environ, find_pg_tool

_logger = logging.getLogger(__name__)

try:
    import boto3
    from boto3.s3.transfer import TransferConfig
    from botocore.config import Config as BotoConfig
except ImportError:  # pragma: no cover
    boto3 = None

PARAM_TARGETS = "offsite_backup.targets"
PARAM_PG_BIN = "offsite_backup.pg_bin_dir"  # optional manual override
CHUNK = 64 * 1024 * 1024  # 64 MB multipart chunks
# The archive keeps every version ever published, in DIST-pgdg-archive.
PGDG_ARCHIVE = "https://apt-archive.postgresql.org/pub/repos/apt"
# First minor release of each major that includes the CVE-2024-7348 fix.
# Those releases make pg_dump read pg_settings ("restrict_nonsystem_relation_kind"),
# which Odoo.sh denies to the tenant role, so we pin to the release just before.
FIRST_FIXED = {12: (12, 20), 13: (13, 16), 14: (14, 13), 15: (15, 8), 16: (16, 4)}
ARCH = {"x86_64": ("amd64", "x86_64-linux-gnu"), "aarch64": ("arm64", "aarch64-linux-gnu")}


def _tool_major(path, env):
    """Return the major version of a pg tool, or 0 if it can't be run."""
    try:
        out = subprocess.run([path, "--version"], env=env, capture_output=True,
                             text=True, timeout=30).stdout
    except Exception:
        return 0
    m = re.search(r"\(PostgreSQL\)\s+(\d+)", out)
    return int(m.group(1)) if m else 0


def _parse_packages(text, wanted):
    """Parse a Debian 'Packages' index -> list of field dicts for wanted packages."""
    found = []
    for stanza in text.split("\n\n"):
        fields = {}
        for line in stanza.splitlines():
            if ": " in line and not line.startswith(" "):
                k, v = line.split(": ", 1)
                fields[k] = v
        if fields.get("Package") in wanted and "Filename" in fields and "Version" in fields:
            found.append(fields)
    return found


def _upstream(version):
    """'16.3-1.pgdg22.04+1' -> (16, 3); None for betas/RCs or odd strings."""
    up = version.split(":")[-1].split("-")[0]
    if "~" in up:
        return None
    try:
        return tuple(int(p) for p in up.split("."))
    except ValueError:
        return None


def _pick_pre_fix(stanzas, major):
    """Newest postgresql-client-<major> older than the CVE-2024-7348 fix,
    plus the libpq5 of the same upstream version (or the newest libpq5)."""
    limit = FIRST_FIXED[major]
    clients = [(v, s) for s in stanzas if s["Package"] == f"postgresql-client-{major}"
               for v in [_upstream(s["Version"])] if v and v[0] == major and v < limit]
    if not clients:
        return None, None
    cver, client = max(clients, key=lambda x: x[0])
    libs = [(v, s) for s in stanzas if s["Package"] == "libpq5"
            for v in [_upstream(s["Version"])] if v]
    same = [x for x in libs if x[0] == cver]
    lib = max(same or libs, key=lambda x: x[0])[1] if libs else None
    return client, lib


class OffsiteBackup(models.AbstractModel):
    _name = "offsite.backup"
    _description = "Off-site database backup"

    # ------------------------------------------------------------------ config
    @api.model
    def _get_targets(self):
        raw = self.env["ir.config_parameter"].sudo().get_param(PARAM_TARGETS, "[]")
        try:
            targets = json.loads(raw)
        except ValueError as e:
            raise UserError(f"{PARAM_TARGETS} is not valid JSON: {e}")
        return [t for t in targets if t.get("bucket")]

    # -------------------------------------------------------------------- dump
    @api.model
    def _make_dump(self, workdir):
        """Build a zip in Odoo's standard backup format
        (dump.sql + filestore/ + manifest.json), so it can be restored with
        the normal database manager or Odoo.sh 'Import Database'."""
        db = self.env.cr.dbname
        stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H-%M-%S")
        sql_path = os.path.join(workdir, "dump.sql")
        zip_path = os.path.join(workdir, f"{db}_{stamp}.zip")

        # pg_dump runs in its own connection with the same PG credentials Odoo
        # uses, so the master password never comes into play.
        pg_dump, env = self._get_pg_dump()
        cmd = [pg_dump, "--no-owner", f"--file={sql_path}", db]
        res = subprocess.run(cmd, env=env,
                             stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        if res.returncode != 0:
            raise UserError(f"pg_dump failed: {res.stderr.decode(errors='replace')}")

        try:
            from odoo.service.db import dump_db_manifest
            manifest = dump_db_manifest(self.env.cr)
        except Exception:  # manifest is nice-to-have, not required
            manifest = {"db_name": db}

        filestore = tools.config.filestore(db)
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED, allowZip64=True) as zf:
            zf.write(sql_path, "dump.sql")
            zf.writestr("manifest.json", json.dumps(manifest, indent=4))
            if os.path.isdir(filestore):
                for root, _dirs, files in os.walk(filestore):
                    for name in files:
                        full = os.path.join(root, name)
                        zf.write(full, os.path.join("filestore", os.path.relpath(full, filestore)))
        os.remove(sql_path)
        return zip_path

    # ---------------------------------------------------------------- pg_dump
    @api.model
    def _get_pg_dump(self):
        """Find a pg_dump whose major version is >= the server's.
        Order: manual override param, previously provisioned copy, any
        /usr/lib/postgresql/*/bin, Odoo's default. If none matches, download
        the official PGDG client into the data dir (no root needed)."""
        self.env.cr.execute("SHOW server_version_num")
        server_major = int(self.env.cr.fetchone()[0]) // 10000

        candidates = []  # (path, libdir or None)
        override = self.env["ir.config_parameter"].sudo().get_param(PARAM_PG_BIN)
        if override:
            candidates.append((os.path.join(override, "pg_dump"), None))
        cached, libdir = self._provisioned_paths(server_major)
        candidates.append((cached, libdir))
        candidates += [(p, None) for p in sorted(glob.glob("/usr/lib/postgresql/*/bin/pg_dump"), reverse=True)]
        try:
            candidates.append((find_pg_tool("pg_dump"), None))
        except Exception:
            pass

        for path, lib in candidates:
            if path and os.path.isfile(path):
                env = self._pg_env(lib)
                if _tool_major(path, env) >= server_major:
                    return path, env

        _logger.info("Off-site backup: no pg_dump >= %s found, provisioning one", server_major)
        self._provision_pg_dump(server_major)
        env = self._pg_env(libdir)
        if _tool_major(cached, env) < server_major:
            raise UserError(f"Provisioned pg_dump at {cached} does not run or is too old.")
        return cached, env

    @api.model
    def _pg_env(self, libdir):
        env = exec_pg_environ()
        if libdir:
            env["LD_LIBRARY_PATH"] = libdir + (":" + env["LD_LIBRARY_PATH"] if env.get("LD_LIBRARY_PATH") else "")
        return env

    @api.model
    def _provisioned_paths(self, major):
        multiarch = ARCH.get(platform.machine(), ("amd64", "x86_64-linux-gnu"))[1]
        root = os.path.join(tools.config["data_dir"], "offsite_backup_pg", f"{major}-pre7348", "root")
        return (os.path.join(root, "usr/lib/postgresql", str(major), "bin/pg_dump"),
                os.path.join(root, "usr/lib", multiarch))

    @api.model
    def _provision_pg_dump(self, major):
        if major not in FIRST_FIXED:
            raise UserError(
                f"PostgreSQL {major} has no pg_dump release that works without reading "
                "pg_settings. Ask Odoo support to grant SELECT on pg_settings.")
        machine = platform.machine()
        if machine not in ARCH:
            raise UserError(f"Unsupported CPU architecture for auto-provisioning: {machine}")
        arch = ARCH[machine][0]
        codename = ""
        with open("/etc/os-release") as f:
            for line in f:
                if line.startswith("VERSION_CODENAME="):
                    codename = line.split("=", 1)[1].strip().strip('"')
        if not codename:
            raise UserError("Could not detect the Ubuntu codename from /etc/os-release.")

        base = os.path.dirname(self._provisioned_paths(major)[0].split("/usr/lib/postgresql/")[0])
        root = os.path.join(base, "root")
        os.makedirs(base, exist_ok=True)
        # Remove the copy an earlier version of this module provisioned (too new to work).
        shutil.rmtree(os.path.join(os.path.dirname(base), str(major)), ignore_errors=True)
        index_url = f"{PGDG_ARCHIVE}/dists/{codename}-pgdg-archive/main/binary-{arch}/Packages.gz"
        try:
            with urllib.request.urlopen(index_url, timeout=300) as r:
                index = gzip.decompress(r.read()).decode("utf-8", "replace")
        except Exception as e:
            raise UserError(
                f"Could not download {index_url} ({e}). Install a PostgreSQL {major} client "
                f"manually and set the system parameter {PARAM_PG_BIN} to its bin directory.")

        stanzas = _parse_packages(index, {f"postgresql-client-{major}", "libpq5"})
        client, lib = _pick_pre_fix(stanzas, major)
        if not client or not lib:
            raise UserError(f"No suitable postgresql-client-{major} / libpq5 found in {index_url}")
        _logger.info("Off-site backup: using postgresql-client-%s %s, libpq5 %s",
                     major, client["Version"], lib["Version"])

        shutil.rmtree(root, ignore_errors=True)
        for pkg in (lib, client):
            filename, sha256 = pkg["Filename"], pkg.get("SHA256")
            deb = os.path.join(base, os.path.basename(filename))
            with urllib.request.urlopen(f"{PGDG_ARCHIVE}/{filename}", timeout=300) as r, open(deb, "wb") as out:
                shutil.copyfileobj(r, out)
            if sha256:
                with open(deb, "rb") as fh:
                    if hashlib.sha256(fh.read()).hexdigest() != sha256:
                        raise UserError(f"Checksum mismatch for {filename}")
            subprocess.run(["dpkg-deb", "-x", deb, root], check=True)
            os.remove(deb)
        _logger.info("Off-site backup: provisioned PostgreSQL %s client in %s", major, root)

    # ------------------------------------------------------------------ upload
    @api.model
    def _client(self, target):
        return boto3.client(
            "s3",
            endpoint_url=target.get("endpoint_url") or None,  # set for B2, omit for AWS
            region_name=target.get("region") or None,
            aws_access_key_id=target["access_key"],
            aws_secret_access_key=target["secret_key"],
            # Avoid boto3>=1.36 default checksum headers that some
            # S3-compatible providers reject.
            config=BotoConfig(request_checksum_calculation="when_required",
                              response_checksum_validation="when_required"),
        )

    @api.model
    def _upload(self, target, path):
        prefix = (target.get("prefix") or "").strip("/")
        key = "/".join(p for p in (prefix, self.env.cr.dbname, os.path.basename(path)) if p)
        cfg = TransferConfig(multipart_threshold=CHUNK, multipart_chunksize=CHUNK)
        self._client(target).upload_file(path, target["bucket"], key, Config=cfg)
        return key

    # -------------------------------------------------------------------- cron
    @api.model
    def _cron_run_backup(self):
        if boto3 is None:
            raise UserError("boto3 is not installed (add it to requirements.txt).")
        targets = self._get_targets()
        if not targets:
            _logger.warning("Off-site backup: no targets configured in %s", PARAM_TARGETS)
            return

        # Use the data dir (persistent disk) rather than /tmp, which can be small.
        base = os.path.join(tools.config["data_dir"], "offsite_backup_tmp")
        os.makedirs(base, exist_ok=True)
        workdir = tempfile.mkdtemp(dir=base)
        errors = []
        try:
            path = self._make_dump(workdir)
            size_mb = os.path.getsize(path) / 1024 / 1024
            for t in targets:
                label = t.get("name") or t["bucket"]
                try:
                    key = self._upload(t, path)
                    _logger.info("Off-site backup: %.1f MB -> %s:%s", size_mb, label, key)
                except Exception as e:
                    _logger.exception("Off-site backup upload to %s failed", label)
                    errors.append(f"{label}: {e}")
        finally:
            shutil.rmtree(workdir, ignore_errors=True)
        if errors:
            raise UserError("Off-site backup failed for: " + "; ".join(errors))