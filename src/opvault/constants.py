"""Magic values and defaults for opvault."""

# Vault directory and file names
VAULT_DIR = ".opvault"
VAULT_CONF = "vault.conf"
VAULT_ENC = "vault.enc"
VAULT_GITIGNORE = ".gitignore"

# Vault config version
VAULT_VERSION = 1

# KDF identifiers
KDF_PBKDF2 = "pbkdf2-sha256"
KDF_ARGON2ID = "argon2id"

# PBKDF2 defaults (OWASP 2024 minimum)
PBKDF2_ITERATIONS = 600_000
PBKDF2_HASH = "sha256"

# Argon2id defaults (OWASP 2024)
ARGON2_TIME_COST = 3
ARGON2_MEMORY_COST = 65536  # 64 MiB
ARGON2_PARALLELISM = 4

# Cryptographic lengths (bytes)
SALT_LENGTH = 32
KEY_LENGTH = 32  # AES-256
NONCE_LENGTH = 12  # GCM standard
VERIFICATION_TOKEN_LENGTH = 32

# Credential types
CREDENTIAL_TYPES = frozenset({
    "password",
    "api_key",
    "token",
    "ssh_key",
    "certificate",
    "hash",
    "cookie",
    "other",
})

DEFAULT_CREDENTIAL_TYPE = "password"
