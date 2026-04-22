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
    """Fetch a specific numbered version of a Secret Manager secret (used for v1 only)."""
    name = f"projects/{sm_project()}/secrets/{secret_id}/versions/{version}"
    resp = _client().access_secret_version(request={"name": name})
    return resp.payload.data.decode("utf-8")


def load_versioned_secret(base_secret_id: str, ver_label: str) -> str:
    """
    Load a rotation key by version label.

    v1  → reads version 1 of the original secret (set up in SETUP.md)
    v2+ → reads the LATEST version of a dedicated named secret
           e.g. ver_label="v2", base="uppass-dek" → secret "uppass-dek-v2"

    This decouples DB version labels from SM auto-increment numbers,
    so destroying old numbered versions can never break startup loading.
    """
    if ver_label == "v1":
        return load_secret_version(base_secret_id, 1)

    named_id = f"{base_secret_id}-{ver_label}"
    name     = f"projects/{sm_project()}/secrets/{named_id}/versions/latest"
    resp     = _client().access_secret_version(request={"name": name})
    return resp.payload.data.decode("utf-8")


def create_versioned_secret(base_secret_id: str, ver_label: str, data: bytes) -> str:
    """
    Store a rotation key as a brand-new dedicated named secret.
    e.g. base="uppass-dek", ver_label="v2" → creates secret "uppass-dek-v2".

    Using a named secret per version means the lookup is always
    load("uppass-dek-v2", latest) — no version number arithmetic,
    no sensitivity to how many times other versions were rotated.
    """
    named_id = f"{base_secret_id}-{ver_label}"
    project  = sm_project()
    client   = _client()
    parent   = f"projects/{project}"

    try:
        client.create_secret(request={
            "parent": parent,
            "secret_id": named_id,
            "secret": {"replication": {"automatic": {}}},
        })
        log.info("Created Secret Manager secret: %s", named_id)
    except Exception as exc:
        # AlreadyExists is fine — just add a new version
        log.info("Secret %s already exists (%s), adding new version", named_id, type(exc).__name__)

    resp = client.add_secret_version(request={
        "parent": f"{parent}/secrets/{named_id}",
        "payload": {"data": data},
    })
    log.info("Stored versioned secret %s: %s", named_id, resp.name)
    return resp.name
