//! TPM 2.0 Constants

pub const EK_RSA_PERSISTENT_HANDLE: u32 = 0x8101_0001;
pub const EK_ECC_PERSISTENT_HANDLE: u32 = 0x8101_0002;

// Well-known NV indices where manufacturers provision the EK certificate
// (per the TCG "EK Credential Profile").
pub const EK_RSA_CERT_NV_INDEX: u32 = 0x01C0_0002;
pub const EK_ECC_CERT_NV_INDEX: u32 = 0x01C0_000A;

// ---------- TPM2 constants ----------

pub const TPM_ST_NO_SESSIONS: u16 = 0x8001;
pub const TPM_CC_READ_PUBLIC: u32 = 0x0000_0173;
pub const TPM_CC_STARTUP: u32 = 0x0000_0144;
pub const TPM_CC_GET_RANDOM: u32 = 0x0000_017B;

/// `startupType` values for `TPM2_Startup`. A simulator's TPM needs one of
/// these before it accepts most other commands; a real firmware-provisioned
/// TPM is already started, so crumpet's Windows backends never needed this.
pub const TPM_SU_CLEAR: u16 = 0x0000;
pub const TPM_SU_STATE: u16 = 0x0001;

pub const TPM_ALG_NULL: u16 = 0x0010;
pub const TPM_ALG_RSA: u16 = 0x0001;
pub const TPM_ALG_ECC: u16 = 0x0023;

pub const TPM_ST_SESSIONS: u16 = 0x8002;
pub const TPM_CC_NV_READ_PUBLIC: u32 = 0x0000_0169;
pub const TPM_CC_NV_READ: u32 = 0x0000_014E;
pub const TPM_CC_GET_CAPABILITY: u32 = 0x0000_017A;
pub const TPM_CAP_TPM_PROPERTIES: u32 = 0x0000_0006;
pub const TPM_PT_NV_BUFFER_MAX: u32 = 0x0000_011B;
pub const TPM_RS_PW: u32 = 0x4000_0009; // "password session" handle for empty-auth

// ---------- Constants for creating a child key under the EK ----------

pub const TPM_RH_ENDORSEMENT: u32 = 0x4000_000B;
pub const TPM_RH_NULL: u32 = 0x4000_0007;

pub const TPM_CC_START_AUTH_SESSION: u32 = 0x0000_0176;
pub const TPM_CC_POLICY_SECRET: u32 = 0x0000_0151;
pub const TPM_CC_CREATE_PRIMARY: u32 = 0x0000_0131;
pub const TPM_CC_CREATE: u32 = 0x0000_0153;
pub const TPM_CC_LOAD: u32 = 0x0000_0157;
pub const TPM_CC_FLUSH_CONTEXT: u32 = 0x0000_0165;
pub const TPM_CC_SIGN: u32 = 0x0000_015D;
pub const TPM_ST_HASHCHECK: u16 = 0x8024;

pub const TPM_SE_POLICY: u8 = 0x01;
pub const TPM_ALG_SHA256: u16 = 0x000B;
pub const TPM_ALG_RSASSA: u16 = 0x0014;

// Bit patterns for TPMA_OBJECT (UINT32)
// 1 << 0 // reserved
pub const TPMA_OBJECT_FIXED_TPM: u32 = 1 << 1;
pub const TPMA_OBJECT_ST_CLEAR: u32 = 1 << 2;
// 1 << 3 // reserved
pub const TPMA_OBJECT_FIXED_PARENT: u32 = 1 << 4;
pub const TPMA_OBJECT_SENSITIVE_DATA_ORIGIN: u32 = 1 << 5;
pub const TPMA_OBJECT_USER_WITH_AUTH: u32 = 1 << 6;
pub const TPMA_OBJECT_ADMIN_WITH_POLICY: u32 = 1 << 7;
pub const TPMA_OBJECT_FIRMWARE_LIMITED: u32 = 1 << 8;
pub const TPMA_OBJECT_SVN_LIMITED: u32 = 1 << 9;
pub const TPMA_OBJECT_NO_DA: u32 = 1 << 10;
pub const TPMA_OBJECT_ENCRYPTED_DUPLICATION: u32 = 1 << 11;
// 1 << 12-15 // reserved
pub const TPMA_OBJECT_RESTRICTED: u32 = 1 << 16;
pub const TPMA_OBJECT_DECRYPT: u32 = 1 << 17;
pub const TPMA_OBJECT_SIGN_ENCRYPT: u32 = 1 << 18;
pub const TPMA_OBJECT_X509_SIGN: u32 = 1 << 19;
// 1 << 20-31 // reserved
