"""Mutable server state — hot-reloadable keys held in process memory."""


class _State:
    def __init__(self):
        self.private_keys: dict        = {}    # version → RSA private key object
        self.current_rsa_version: str  = "v1"
        self.dek_keys: dict            = {}    # version → 32-byte AES key (bytes)
        self.current_dek_version: str  = "v1"
        self.hmac_secrets: dict        = {}    # version → bytes
        self.current_hmac_version: str = "v1"


state = _State()
