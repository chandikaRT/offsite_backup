import json
import logging
import os
import shutil
import subprocess
import tempfile
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
CHUNK = 64 * 1024 * 1024  # 64 MB multipart chunks


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
        cmd = [find_pg_tool("pg_dump"), "--no-owner", f"--file={sql_path}", db]
        res = subprocess.run(cmd, env=exec_pg_environ(),
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
