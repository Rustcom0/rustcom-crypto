#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

mod bip39_wordlist;
pub mod ed25519;
pub mod error;
pub mod private_product;
pub mod rcenc;
pub mod rcstr;
pub mod recovery;
pub mod shamir;
pub mod skl;
pub mod staff_grant;
pub mod strict_id;
pub mod types;
pub mod xwing;

pub use ed25519::{
    ED25519_PUBLIC_KEY_LEN, ED25519_SECRET_SEED_LEN, ED25519_SIGNATURE_LEN, Ed25519SigningKey,
    Ed25519VerifyingKey,
};
pub use error::CryptoError;
pub use private_product::{
    ARGON2_KEM_DATA_LEN, ARGON2_SALT_LEN, Argon2idBudget, Argon2idKemData, Argon2idParams,
    DEFAULT_ARGON2_M_COST_KIB, DEFAULT_ARGON2_P_COST, DEFAULT_ARGON2_T_COST, MAX_ARGON2_M_COST_KIB,
    MAX_ARGON2_P_COST, MAX_ARGON2_T_COST, MAX_ARGON2_WORK_KIB_ITERS, MAX_PASSWORD_LEN,
    MIN_ARGON2_M_COST_KIB, MIN_ARGON2_P_COST, MIN_ARGON2_T_COST, VIP_FRAGMENT_CHK_CONTEXT,
    VIP_FRAGMENT_MAX_INPUT_LEN, VIP_FRAGMENT_RAW_LEN, VIP_FRAGMENT_TOKEN_LEN,
    VIP_FRAGMENT_VERSION_V1, VIP_GROUP_KEY_WRAP_SCHEMA_VERSION, VIP_KEY_WRAP_MAGIC,
    VIP_KEY_WRAP_PAYLOAD_LEN, VIP_KEY_WRAP_VERSION_V1, VipInviteFragment,
    WASM_MAX_ARGON2_M_COST_KIB, WASM_MAX_ARGON2_P_COST, WASM_MAX_ARGON2_T_COST,
    WASM_MAX_ARGON2_WORK_KIB_ITERS, decrypt_private_product_password,
    decrypt_private_product_password_version, decrypt_private_product_password_version_with_budget,
    decrypt_private_product_password_with_budget, decrypt_private_product_vip,
    decrypt_private_product_vip_fragment, derive_password_kek, encrypt_private_product_password,
    encrypt_private_product_password_with_rng, encrypt_private_product_vip,
    encrypt_private_product_vip_with_rng, extract_password_slot, unwrap_vip_group_key,
    wrap_vip_group_key, wrap_vip_group_key_with_rng,
};
pub use rcenc::{
    AEAD_TAG_LEN, CIPHER_SUITE_XWING_XCHACHA20_POLY1305, DecryptedEnvelope, EnvelopeHeader,
    MAX_RCENC_PAYLOAD_CIPHERTEXT_LEN, MAX_RECIPIENTS, ParsedEnvelope, ParsedRecipientSlot,
    RCENC_FORMAT_VERSION_V1, RCENC_HEADER_LEN, RCENC_MAGIC, RecipientCredential, RecipientSpec,
    WRAPPED_DEK_LEN, XCHACHA_NONCE_LEN, build_canonical_aad, decrypt, encrypt, encrypt_with_rng,
    parse_envelope, parse_envelope_prefix,
};
pub use rcstr::{
    DEFAULT_CHUNK_SIZE, FILE_NONCE_PREFIX_LEN, MAX_CHUNK_INDEX, MAX_CHUNK_SIZE, MIN_CHUNK_SIZE,
    RCSTR_FIXED_HEADER_LEN, RCSTR_FORMAT_VERSION_V1, RCSTR_MAGIC, RcstrDecryptor, RcstrEncryptor,
    decrypt_stream, encrypt_stream, encrypt_stream_with_rng,
};
pub use recovery::{
    BIP39_MAX_INPUT_LEN, BIP39_WORD_COUNT, OrgKeyBackupEntry, RECOVERY_BACKUP_ENTRY_LEN,
    RECOVERY_BACKUP_HEADER_LEN, RECOVERY_BACKUP_MAGIC, RECOVERY_BACKUP_MAX_KEYS,
    RECOVERY_BACKUP_SCHEMA_VERSION, RECOVERY_BACKUP_VERSION_V1, RECOVERY_KEK_INFO,
    RECOVERY_SECRET_LEN, RecoveredOrgKey, RecoveryBundle, RecoveryMasterSecret,
    unwrap_recovery_backup, wrap_recovery_backup, wrap_recovery_backup_with_rng,
};
pub use shamir::{
    MAX_SHAMIR_SHARES, MIN_SHAMIR_THRESHOLD, SHAMIR_COMMIT_DOMAIN, SHAMIR_SECRET_LEN,
    SHAMIR_SHARE_MAGIC, SHAMIR_SHARE_VERSION_V1, SHAMIR_SHARE_WIRE_LEN, ShamirShare,
    combine_recovery_shares, split_recovery_secret, split_recovery_secret_with_rng,
};
pub use skl::{
    MAX_SKL_ENTRIES, SKL_BODY_LEN, SKL_ENTRY_BASE_WIRE_LEN, SKL_ENTRY_DOMAIN,
    SKL_ENTRY_ROTATE_WIRE_LEN, SKL_ENTRY_VERSION_V1, SKL_ROTATE_DOMAIN, SKL_ROTATE_MSG_LEN,
    SklCheckpoint, SklEntryV1, VerifiedSkl, verify_skl_chain,
};
pub use staff_grant::{
    ORG_KEY_ARCHIVE_MAGIC, ORG_KEY_ARCHIVE_PAYLOAD_LEN, ORG_KEY_ARCHIVE_SCHEMA_VERSION,
    ORG_KEY_ARCHIVE_VERSION_V1, STAFF_GRANT_DOMAIN, STAFF_GRANT_MSG_LEN, STAFF_GRANT_VERSION_V1,
    STAFF_GRANT_WIRE_LEN, STAFF_KEY_WRAP_MAGIC, STAFF_KEY_WRAP_PAYLOAD_LEN,
    STAFF_KEY_WRAP_SCHEMA_VERSION, STAFF_KEY_WRAP_VERSION_V1, StaffGrantV1, VaultRole,
    archive_org_key, archive_org_key_with_rng, hash_xwing_public_key, unwrap_archived_org_key,
    unwrap_staff_org_key, wrap_staff_org_key, wrap_staff_org_key_with_rng,
};
pub use strict_id::{
    STRICT_ACCOUNT_ID_BYTES_LEN, STRICT_ACCOUNT_ID_CHECKSUM_CHARS, STRICT_ACCOUNT_ID_CHK_CONTEXT,
    STRICT_ACCOUNT_ID_DATA_CHARS, STRICT_ACCOUNT_ID_FORMATTED_LEN, STRICT_ACCOUNT_ID_MAX_INPUT_LEN,
    STRICT_ACCOUNT_ID_TOTAL_CHARS, STRICT_AUTH_INFO, STRICT_LOOKUP_INFO, STRICT_VAULT_ED25519_INFO,
    STRICT_VAULT_INFO, STRICT_VAULT_XWING_INFO, StrictAccountId, StrictClientKeys,
    StrictCustomerVault, compute_strict_lookup_index,
};
pub use types::{
    EnvelopeContext, EnvelopeFlags, EnvelopeKind, PrivacyTier, RecipientType, SymmetricKey,
};
pub use xwing::{
    XWING_CIPHERTEXT_LEN, XWING_PUBLIC_KEY_LEN, XWING_SECRET_SEED_LEN, XWingPublicKey,
    XWingSecretKey,
};
