"""Google Cloud helpers — Secret Manager read/write."""

import os
import logging
import subprocess

log = logging.getLogger("uppass")

_GCP_PROJECT_ID = os.environ.get("GOOGLE_CLOUD_PROJECT", "")


def sm_project() -> str:
    project = _GCP_PROJECT_ID
    if not project:
        try:
            result = subprocess.run(
                ["gcloud", "config", "get-value", "project"],
                capture_output=True, text=True, timeout=5,
            )
            project = result.stdout.strip()
        except Exception:
            pass
    if not project:
        raise RuntimeError("Cannot determine GCP project — set GOOGLE_CLOUD_PROJECT env var")
    return project


def _client():
    from google.cloud import secretmanager
    return secretmanager.SecretManagerServiceClient()


def load_secret_version(secret_id: str, version: int) -> str:
    """Fetch a specific numbered version of a Secret Manager secret."""
    name = f"projects/{sm_project()}/secrets/{secret_id}/versions/{version}"
    resp = _client().access_secret_version(request={"name": name})
    return resp.payload.data.decode("utf-8")


def store_secret_version(secret_id: str, data: bytes) -> str:
    """Add a new version to an existing Secret Manager secret. Returns version name."""
    parent = f"projects/{sm_project()}/secrets/{secret_id}"
    resp   = _client().add_secret_version(
        request={"parent": parent, "payload": {"data": data}}
    )
    log.info("Stored new secret version: %s", resp.name)
    return resp.name
