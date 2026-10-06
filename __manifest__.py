{
    "name": "Off-site Backup (S3 / Backblaze B2)",
    "version": "17.0.1.0.0",
    "summary": "Daily DB + filestore dump uploaded to S3-compatible storage, no master password needed",
    "depends": ["base"],
    "data": ["data/ir_cron.xml"],
    "external_dependencies": {"python": ["boto3"]},
    "license": "LGPL-3",
    "installable": True,
}
