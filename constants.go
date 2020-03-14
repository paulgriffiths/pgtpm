package pgtpm

import (
	"encoding/json"
	"fmt"
)

// Algorithm is a TPM2_ALG_ID Constant.
type Algorithm uint16

// AlgorithmAttribute is a UINT32 TPMA_ALGORITHM Bit Constant.
type AlgorithmAttribute uint32

// Capability is a UINT32 TPM2_CAP Constant.
type Capability uint32

// Command is a TPM2_CC Constant.
type Command uint32

// EllipticCurve is a TPM2_ECC_CURVE Constant.
type EllipticCurve uint16

// Handle is a handle value.
type Handle uint32

// HandleType is a UINT8 TPM2_HT Constant.
type HandleType uint32

// ObjectAttribute is a UINT32 TPMA_OBJECT Bit Constant.
type ObjectAttribute uint32

// Algorithm constants.
const (
	TPM2_ALG_ERROR          Algorithm = 0x0000
	TPM2_ALG_RSA            Algorithm = 0x0001
	TPM2_ALG_TDES           Algorithm = 0x0003
	TPM2_ALG_SHA1           Algorithm = 0x0004
	TPM2_ALG_HMAC           Algorithm = 0x0005
	TPM2_ALG_AES            Algorithm = 0x0006
	TPM2_ALG_MGF1           Algorithm = 0x0007
	TPM2_ALG_KEYEDHASH      Algorithm = 0x0008
	TPM2_ALG_XOR            Algorithm = 0x000a
	TPM2_ALG_SHA256         Algorithm = 0x000b
	TPM2_ALG_SHA384         Algorithm = 0x000c
	TPM2_ALG_SHA512         Algorithm = 0x000d
	TPM2_ALG_NULL           Algorithm = 0x0010
	TPM2_ALG_SM3_256        Algorithm = 0x0012
	TPM2_ALG_SM4            Algorithm = 0x0013
	TPM2_ALG_RSASSA         Algorithm = 0x0014
	TPM2_ALG_RSAES          Algorithm = 0x0015
	TPM2_ALG_RSAPSS         Algorithm = 0x0016
	TPM2_ALG_OAEP           Algorithm = 0x0017
	TPM2_ALG_ECDSA          Algorithm = 0x0018
	TPM2_ALG_ECDH           Algorithm = 0x0019
	TPM2_ALG_ECDAA          Algorithm = 0x001a
	TPM2_ALG_SM2            Algorithm = 0x001b
	TPM2_ALG_ECSCHNORR      Algorithm = 0x001c
	TPM2_ALG_ECMQV          Algorithm = 0x001d
	TPM2_ALG_KDF1_SP800_56A Algorithm = 0x0020
	TPM2_ALG_KDF2           Algorithm = 0x0021
	TPM2_ALG_KDF1_SP800_108 Algorithm = 0x0022
	TPM2_ALG_ECC            Algorithm = 0x0023
	TPM2_ALG_SYMCIPHER      Algorithm = 0x0025
	TPM2_ALG_CAMELLIA       Algorithm = 0x0026
	TPM2_ALG_SHA3_256       Algorithm = 0x0027
	TPM2_ALG_SHA3_384       Algorithm = 0x0028
	TPM2_ALG_SHA3_512       Algorithm = 0x0029
	TPM2_ALG_CMAC           Algorithm = 0x003f
	TPM2_ALG_CTR            Algorithm = 0x0040
	TPM2_ALG_OFB            Algorithm = 0x0041
	TPM2_ALG_CBC            Algorithm = 0x0042
	TPM2_ALG_CFB            Algorithm = 0x0043
	TPM2_ALG_ECB            Algorithm = 0x0044
)

// Algorithm attribute constants.
const (
	TPMA_ALGORITHM_ASYMMETRIC AlgorithmAttribute = 0x0001
	TPMA_ALGORITHM_SYMMETRIC  AlgorithmAttribute = 0x0002
	TPMA_ALGORITHM_HASH       AlgorithmAttribute = 0x0004
	TPMA_ALGORITHM_OBJECT     AlgorithmAttribute = 0x0008
	TPMA_ALGORITHM_SIGNING    AlgorithmAttribute = 0x0100
	TPMA_ALGORITHM_ENCRYPTING AlgorithmAttribute = 0x0200
	TPMA_ALGORITHM_METHOD     AlgorithmAttribute = 0x0400
)

// Elliptic curve constants.
const (
	TPM2_ECC_NONE      EllipticCurve = 0x0000
	TPM2_ECC_NIST_P192 EllipticCurve = 0x0001
	TPM2_ECC_NIST_P224 EllipticCurve = 0x0002
	TPM2_ECC_NIST_P256 EllipticCurve = 0x0003
	TPM2_ECC_NIST_P384 EllipticCurve = 0x0004
	TPM2_ECC_NIST_P521 EllipticCurve = 0x0005
	TPM2_ECC_BN_P256   EllipticCurve = 0x0010
	TPM2_ECC_BN_P638   EllipticCurve = 0x0011
	TPM2_ECC_SM2_P256  EllipticCurve = 0x0020
)

// Handle type constants.
const (
	TPM2_HT_PCR            HandleType = 0x00
	TPM2_HT_NV_INDEX       HandleType = 0x01
	TPM2_HT_HMAC_SESSION   HandleType = 0x02
	TPM2_HT_LOADED_SESSION HandleType = 0x02
	TPM2_HT_POLICY_SESSION HandleType = 0x03
	TPM2_HT_SAVED_SESSION  HandleType = 0x03
	TPM2_HT_PERMANENT      HandleType = 0x40
	TPM2_HT_TRANSIENT      HandleType = 0x80
	TPM2_HT_PERSISTENT     HandleType = 0x81
)

// Handle mask, range and shift values.
const (
	TPM2_HR_HANDLE_MASK uint32 = 0x00FFFFFF
	TPM2_HR_RANGE_MASK  uint32 = 0xFF000000
	TPM2_HR_SHIFT       uint32 = 24
)

// Capability constants.
const (
	TPM2_CAP_FIRST           Capability = 0x00000000
	TPM2_CAP_ALGS            Capability = 0x00000000
	TPM2_CAP_HANDLES         Capability = 0x00000001
	TPM2_CAP_COMMANDS        Capability = 0x00000002
	TPM2_CAP_PP_COMMANDS     Capability = 0x00000003
	TPM2_CAP_AUDIT_COMMANDS  Capability = 0x00000004
	TPM2_CAP_PCRS            Capability = 0x00000005
	TPM2_CAP_TPM_PROPERTIES  Capability = 0x00000006
	TPM2_CAP_PCR_PROPERTIES  Capability = 0x00000007
	TPM2_CAP_ECC_CURVES      Capability = 0x00000008
	TPM2_CAP_LAST            Capability = 0x00000008
	TPM2_CAP_VENDOR_PROPERTY Capability = 0x00000100
)

// Command constants.
const (
	TPM2_CC_NV_UndefineSpaceSpecial    Command = 0x0000011f
	TPM2_CC_EvictControl               Command = 0x00000120
	TPM2_CC_HierarchyControl           Command = 0x00000121
	TPM2_CC_NV_UndefineSpace           Command = 0x00000122
	TPM2_CC_ChangeEPS                  Command = 0x00000124
	TPM2_CC_ChangePPS                  Command = 0x00000125
	TPM2_CC_Clear                      Command = 0x00000126
	TPM2_CC_ClearControl               Command = 0x00000127
	TPM2_CC_ClockSet                   Command = 0x00000128
	TPM2_CC_HierarchyChangeAuth        Command = 0x00000129
	TPM2_CC_NV_DefineSpace             Command = 0x0000012a
	TPM2_CC_PCR_Allocate               Command = 0x0000012b
	TPM2_CC_PCR_SetAuthPolicy          Command = 0x0000012c
	TPM2_CC_PP_Commands                Command = 0x0000012d
	TPM2_CC_SetPrimaryPolicy           Command = 0x0000012e
	TPM2_CC_FieldUpgradeStart          Command = 0x0000012f
	TPM2_CC_ClockRateAdjust            Command = 0x00000130
	TPM2_CC_CreatePrimary              Command = 0x00000131
	TPM2_CC_NV_GlobalWriteLock         Command = 0x00000132
	TPM2_CC_GetCommandAuditDigest      Command = 0x00000133
	TPM2_CC_NV_Increment               Command = 0x00000134
	TPM2_CC_NV_SetBits                 Command = 0x00000135
	TPM2_CC_NV_Extend                  Command = 0x00000136
	TPM2_CC_NV_Write                   Command = 0x00000137
	TPM2_CC_NV_WriteLock               Command = 0x00000138
	TPM2_CC_DictionaryAttackLockReset  Command = 0x00000139
	TPM2_CC_DictionaryAttackParameters Command = 0x0000013a
	TPM2_CC_NV_ChangeAuth              Command = 0x0000013b
	TPM2_CC_PCR_Event                  Command = 0x0000013c
	TPM2_CC_PCR_Reset                  Command = 0x0000013d
	TPM2_CC_SequenceComplete           Command = 0x0000013e
	TPM2_CC_SetAlgorithmSet            Command = 0x0000013f
	TPM2_CC_SetCommandCodeAuditStatus  Command = 0x00000140
	TPM2_CC_FieldUpgradeData           Command = 0x00000141
	TPM2_CC_IncrementalSelfTest        Command = 0x00000142
	TPM2_CC_SelfTest                   Command = 0x00000143
	TPM2_CC_Startup                    Command = 0x00000144
	TPM2_CC_Shutdown                   Command = 0x00000145
	TPM2_CC_StirRandom                 Command = 0x00000146
	TPM2_CC_ActivateCredential         Command = 0x00000147
	TPM2_CC_Certify                    Command = 0x00000148
	TPM2_CC_PolicyNV                   Command = 0x00000149
	TPM2_CC_CertifyCreation            Command = 0x0000014a
	TPM2_CC_Duplicate                  Command = 0x0000014b
	TPM2_CC_GetTime                    Command = 0x0000014c
	TPM2_CC_GetSessionAuditDigest      Command = 0x0000014d
	TPM2_CC_NV_Read                    Command = 0x0000014e
	TPM2_CC_NV_ReadLock                Command = 0x0000014f
	TPM2_CC_ObjectChangeAuth           Command = 0x00000150
	TPM2_CC_PolicySecret               Command = 0x00000151
	TPM2_CC_Rewrap                     Command = 0x00000152
	TPM2_CC_Create                     Command = 0x00000153
	TPM2_CC_ECDH_ZGen                  Command = 0x00000154
	TPM2_CC_HMAC                       Command = 0x00000155
	TPM2_CC_Import                     Command = 0x00000156
	TPM2_CC_Load                       Command = 0x00000157
	TPM2_CC_Quote                      Command = 0x00000158
	TPM2_CC_RSA_Decrypt                Command = 0x00000159
	TPM2_CC_HMAC_Start                 Command = 0x0000015b
	TPM2_CC_SequenceUpdate             Command = 0x0000015c
	TPM2_CC_Sign                       Command = 0x0000015d
	TPM2_CC_Unseal                     Command = 0x0000015e
	TPM2_CC_PolicySigned               Command = 0x00000160
	TPM2_CC_ContextLoad                Command = 0x00000161
	TPM2_CC_ContextSave                Command = 0x00000162
	TPM2_CC_ECDH_KeyGen                Command = 0x00000163
	TPM2_CC_EncryptDecrypt             Command = 0x00000164
	TPM2_CC_FlushContext               Command = 0x00000165
	TPM2_CC_LoadExternal               Command = 0x00000167
	TPM2_CC_MakeCredential             Command = 0x00000168
	TPM2_CC_NV_ReadPublic              Command = 0x00000169
	TPM2_CC_PolicyAuthorize            Command = 0x0000016a
	TPM2_CC_PolicyAuthValue            Command = 0x0000016b
	TPM2_CC_PolicyCommandCode          Command = 0x0000016c
	TPM2_CC_PolicyCounterTimer         Command = 0x0000016d
	TPM2_CC_PolicyCpHash               Command = 0x0000016e
	TPM2_CC_PolicyLocality             Command = 0x0000016f
	TPM2_CC_PolicyNameHash             Command = 0x00000170
	TPM2_CC_PolicyOR                   Command = 0x00000171
	TPM2_CC_PolicyTicket               Command = 0x00000172
	TPM2_CC_ReadPublic                 Command = 0x00000173
	TPM2_CC_RSA_Encrypt                Command = 0x00000174
	TPM2_CC_StartAuthSession           Command = 0x00000176
	TPM2_CC_VerifySignature            Command = 0x00000177
	TPM2_CC_ECC_Parameters             Command = 0x00000178
	TPM2_CC_FirmwareRead               Command = 0x00000179
	TPM2_CC_GetCapability              Command = 0x0000017a
	TPM2_CC_GetRandom                  Command = 0x0000017b
	TPM2_CC_GetTestResult              Command = 0x0000017c
	TPM2_CC_Hash                       Command = 0x0000017d
	TPM2_CC_PCR_Read                   Command = 0x0000017e
	TPM2_CC_PolicyPCR                  Command = 0x0000017f
	TPM2_CC_PolicyRestart              Command = 0x00000180
	TPM2_CC_ReadClock                  Command = 0x00000181
	TPM2_CC_PCR_Extend                 Command = 0x00000182
	TPM2_CC_PCR_SetAuthValue           Command = 0x00000183
	TPM2_CC_NV_Certify                 Command = 0x00000184
	TPM2_CC_EventSequenceComplete      Command = 0x00000185
	TPM2_CC_HashSequenceStart          Command = 0x00000186
	TPM2_CC_PolicyPhysicalPresence     Command = 0x00000187
	TPM2_CC_PolicyDuplicationSelect    Command = 0x00000188
	TPM2_CC_PolicyGetDigest            Command = 0x00000189
	TPM2_CC_TestParms                  Command = 0x0000018a
	TPM2_CC_Commit                     Command = 0x0000018b
	TPM2_CC_PolicyPassword             Command = 0x0000018c
	TPM2_CC_ZGen_2Phase                Command = 0x0000018d
	TPM2_CC_EC_Ephemeral               Command = 0x0000018e
	TPM2_CC_PolicyNvWritten            Command = 0x0000018f
	TPM2_CC_PolicyTemplate             Command = 0x00000190
	TPM2_CC_CreateLoaded               Command = 0x00000191
	TPM2_CC_PolicyAuthorizeNV          Command = 0x00000192
	TPM2_CC_EncryptDecrypt2            Command = 0x00000193
	TPM2_CC_AC_GetCapability           Command = 0x00000194
	TPM2_CC_AC_Send                    Command = 0x00000195
	TPM2_CC_Policy_AC_SendSelect       Command = 0x00000196
	TPM2_CC_LAST                       Command = 0x00000196
	TPM2_CC_Vendor_TCG_Test            Command = 0x20000000
)

// Object attribute constants.
const (
	TPMA_OBJECT_FIXEDTPM             ObjectAttribute = 0x00000002
	TPMA_OBJECT_STCLEAR              ObjectAttribute = 0x00000004
	TPMA_OBJECT_FIXEDPARENT          ObjectAttribute = 0x00000010
	TPMA_OBJECT_SENSITIVEDATAORIGIN  ObjectAttribute = 0x00000020
	TPMA_OBJECT_USERWITHAUTH         ObjectAttribute = 0x00000040
	TPMA_OBJECT_ADMINWITHPOLICY      ObjectAttribute = 0x00000080
	TPMA_OBJECT_NODA                 ObjectAttribute = 0x00000400
	TPMA_OBJECT_ENCRYPTEDDUPLICATION ObjectAttribute = 0x00000800
	TPMA_OBJECT_RESTRICTED           ObjectAttribute = 0x00010000
	TPMA_OBJECT_DECRYPT              ObjectAttribute = 0x00020000
	TPMA_OBJECT_SIGN_ENCRYPT         ObjectAttribute = 0x00040000
)

// Permanent handle constants.
const (
	TPM2_RH_FIRST       Handle = 0x40000000
	TPM2_RH_SRK         Handle = 0x40000000
	TPM2_RH_OWNER       Handle = 0x40000001
	TPM2_RH_REVOKE      Handle = 0x40000002
	TPM2_RH_TRANSPORT   Handle = 0x40000003
	TPM2_RH_OPERATOR    Handle = 0x40000004
	TPM2_RH_ADMIN       Handle = 0x40000005
	TPM2_RH_EK          Handle = 0x40000006
	TPM2_RH_NULL        Handle = 0x40000007
	TPM2_RH_UNASSIGNED  Handle = 0x40000008
	TPM2_RS_PW          Handle = 0x40000009
	TPM2_RH_LOCKOUT     Handle = 0x4000000A
	TPM2_RH_ENDORSEMENT Handle = 0x4000000B
	TPM2_RH_PLATFORM    Handle = 0x4000000C
	TPM2_RH_PLATFORM_NV Handle = 0x4000000D
	TPM2_RH_AUTH_00     Handle = 0x40000010
	TPM2_RH_AUTH_FF     Handle = 0x4000010F
	TPM2_RH_LAST        Handle = 0x4000010F
)

// algToString maps Algorithm values to their string representations.
var algToString = map[Algorithm]string{
	TPM2_ALG_ERROR:          "TPM2_ALG_ERROR",
	TPM2_ALG_RSA:            "TPM2_ALG_RSA",
	TPM2_ALG_TDES:           "TPM2_ALG_TDES",
	TPM2_ALG_SHA1:           "TPM2_ALG_SHA1",
	TPM2_ALG_HMAC:           "TPM2_ALG_HMAC",
	TPM2_ALG_AES:            "TPM2_ALG_AES",
	TPM2_ALG_MGF1:           "TPM2_ALG_MGF1",
	TPM2_ALG_KEYEDHASH:      "TPM2_ALG_KEYEDHASH",
	TPM2_ALG_XOR:            "TPM2_ALG_XOR",
	TPM2_ALG_SHA256:         "TPM2_ALG_SHA256",
	TPM2_ALG_SHA384:         "TPM2_ALG_SHA384",
	TPM2_ALG_SHA512:         "TPM2_ALG_SHA512",
	TPM2_ALG_NULL:           "TPM2_ALG_NULL",
	TPM2_ALG_SM3_256:        "TPM2_ALG_SM3_256",
	TPM2_ALG_SM4:            "TPM2_ALG_SM4",
	TPM2_ALG_RSASSA:         "TPM2_ALG_RSASSA",
	TPM2_ALG_RSAES:          "TPM2_ALG_RSAES",
	TPM2_ALG_RSAPSS:         "TPM2_ALG_RSAPSS",
	TPM2_ALG_OAEP:           "TPM2_ALG_OAEP",
	TPM2_ALG_ECDSA:          "TPM2_ALG_ECDSA",
	TPM2_ALG_ECDH:           "TPM2_ALG_ECDH",
	TPM2_ALG_ECDAA:          "TPM2_ALG_ECDAA",
	TPM2_ALG_SM2:            "TPM2_ALG_SM2",
	TPM2_ALG_ECSCHNORR:      "TPM2_ALG_ECSCHNORR",
	TPM2_ALG_ECMQV:          "TPM2_ALG_ECMQV",
	TPM2_ALG_KDF1_SP800_56A: "TPM2_ALG_KDF1_SP800_56A",
	TPM2_ALG_KDF2:           "TPM2_ALG_KDF2",
	TPM2_ALG_KDF1_SP800_108: "TPM2_ALG_KDF1_SP800_108",
	TPM2_ALG_ECC:            "TPM2_ALG_ECC",
	TPM2_ALG_SYMCIPHER:      "TPM2_ALG_SYMCIPHER",
	TPM2_ALG_CAMELLIA:       "TPM2_ALG_CAMELLIA",
	TPM2_ALG_SHA3_256:       "TPM2_ALG_SHA3_256",
	TPM2_ALG_SHA3_384:       "TPM2_ALG_SHA3_384",
	TPM2_ALG_SHA3_512:       "TPM2_ALG_SHA3_512",
	TPM2_ALG_CMAC:           "TPM2_ALG_CMAC",
	TPM2_ALG_CTR:            "TPM2_ALG_CTR",
	TPM2_ALG_OFB:            "TPM2_ALG_OFB",
	TPM2_ALG_CBC:            "TPM2_ALG_CBC",
	TPM2_ALG_CFB:            "TPM2_ALG_CFB",
	TPM2_ALG_ECB:            "TPM2_ALG_ECB",
}

// stringToAlg maps Algorithm string representations to their values.
var stringToAlg = map[string]Algorithm{
	"TPM2_ALG_ERROR":          TPM2_ALG_ERROR,
	"TPM2_ALG_RSA":            TPM2_ALG_RSA,
	"TPM2_ALG_TDES":           TPM2_ALG_TDES,
	"TPM2_ALG_SHA1":           TPM2_ALG_SHA1,
	"TPM2_ALG_HMAC":           TPM2_ALG_HMAC,
	"TPM2_ALG_AES":            TPM2_ALG_AES,
	"TPM2_ALG_MGF1":           TPM2_ALG_MGF1,
	"TPM2_ALG_KEYEDHASH":      TPM2_ALG_KEYEDHASH,
	"TPM2_ALG_XOR":            TPM2_ALG_XOR,
	"TPM2_ALG_SHA256":         TPM2_ALG_SHA256,
	"TPM2_ALG_SHA384":         TPM2_ALG_SHA384,
	"TPM2_ALG_SHA512":         TPM2_ALG_SHA512,
	"TPM2_ALG_NULL":           TPM2_ALG_NULL,
	"TPM2_ALG_SM3_256":        TPM2_ALG_SM3_256,
	"TPM2_ALG_SM4":            TPM2_ALG_SM4,
	"TPM2_ALG_RSASSA":         TPM2_ALG_RSASSA,
	"TPM2_ALG_RSAES":          TPM2_ALG_RSAES,
	"TPM2_ALG_RSAPSS":         TPM2_ALG_RSAPSS,
	"TPM2_ALG_OAEP":           TPM2_ALG_OAEP,
	"TPM2_ALG_ECDSA":          TPM2_ALG_ECDSA,
	"TPM2_ALG_ECDH":           TPM2_ALG_ECDH,
	"TPM2_ALG_ECDAA":          TPM2_ALG_ECDAA,
	"TPM2_ALG_SM2":            TPM2_ALG_SM2,
	"TPM2_ALG_ECSCHNORR":      TPM2_ALG_ECSCHNORR,
	"TPM2_ALG_ECMQV":          TPM2_ALG_ECMQV,
	"TPM2_ALG_KDF1_SP800_56A": TPM2_ALG_KDF1_SP800_56A,
	"TPM2_ALG_KDF2":           TPM2_ALG_KDF2,
	"TPM2_ALG_KDF1_SP800_108": TPM2_ALG_KDF1_SP800_108,
	"TPM2_ALG_ECC":            TPM2_ALG_ECC,
	"TPM2_ALG_SYMCIPHER":      TPM2_ALG_SYMCIPHER,
	"TPM2_ALG_CAMELLIA":       TPM2_ALG_CAMELLIA,
	"TPM2_ALG_SHA3_256":       TPM2_ALG_SHA3_256,
	"TPM2_ALG_SHA3_384":       TPM2_ALG_SHA3_384,
	"TPM2_ALG_SHA3_512":       TPM2_ALG_SHA3_512,
	"TPM2_ALG_CMAC":           TPM2_ALG_CMAC,
	"TPM2_ALG_CTR":            TPM2_ALG_CTR,
	"TPM2_ALG_OFB":            TPM2_ALG_OFB,
	"TPM2_ALG_CBC":            TPM2_ALG_CBC,
	"TPM2_ALG_CFB":            TPM2_ALG_CFB,
	"TPM2_ALG_ECB":            TPM2_ALG_ECB,
}

// algAttrToString maps AlgorithmAttribute values to their string representations.
var algAttrToString = map[AlgorithmAttribute]string{
	TPMA_ALGORITHM_ASYMMETRIC: "TPMA_ALGORITHM_ASYMMETRIC",
	TPMA_ALGORITHM_SYMMETRIC:  "TPMA_ALGORITHM_SYMMETRIC",
	TPMA_ALGORITHM_HASH:       "TPMA_ALGORITHM_HASH",
	TPMA_ALGORITHM_OBJECT:     "TPMA_ALGORITHM_OBJECT",
	TPMA_ALGORITHM_SIGNING:    "TPMA_ALGORITHM_SIGNING",
	TPMA_ALGORITHM_ENCRYPTING: "TPMA_ALGORITHM_ENCRYPTING",
	TPMA_ALGORITHM_METHOD:     "TPMA_ALGORITHM_METHOD",
}

// stringToAlgAttr maps AlgorithmAttribute string representations to their values.
var stringToAlgAttr = map[string]AlgorithmAttribute{
	"TPMA_ALGORITHM_ASYMMETRIC": TPMA_ALGORITHM_ASYMMETRIC,
	"TPMA_ALGORITHM_SYMMETRIC":  TPMA_ALGORITHM_SYMMETRIC,
	"TPMA_ALGORITHM_HASH":       TPMA_ALGORITHM_HASH,
	"TPMA_ALGORITHM_OBJECT":     TPMA_ALGORITHM_OBJECT,
	"TPMA_ALGORITHM_SIGNING":    TPMA_ALGORITHM_SIGNING,
	"TPMA_ALGORITHM_ENCRYPTING": TPMA_ALGORITHM_ENCRYPTING,
	"TPMA_ALGORITHM_METHOD":     TPMA_ALGORITHM_METHOD,
}

// capToString maps Capability values to their string representations.
var capToString = map[Capability]string{
	TPM2_CAP_ALGS:            "TPM2_CAP_ALGS",
	TPM2_CAP_HANDLES:         "TPM2_CAP_HANDLES",
	TPM2_CAP_COMMANDS:        "TPM2_CAP_COMMANDS",
	TPM2_CAP_PP_COMMANDS:     "TPM2_CAP_PP_COMMANDS",
	TPM2_CAP_AUDIT_COMMANDS:  "TPM2_CAP_AUDIT_COMMANDS",
	TPM2_CAP_PCRS:            "TPM2_CAP_PCRS",
	TPM2_CAP_TPM_PROPERTIES:  "TPM2_CAP_TPM_PROPERTIES",
	TPM2_CAP_PCR_PROPERTIES:  "TPM2_CAP_PCR_PROPERTIES",
	TPM2_CAP_ECC_CURVES:      "TPM2_CAP_ECC_CURVES",
	TPM2_CAP_VENDOR_PROPERTY: "TPM2_CAP_VENDOR_PROPERTY",
}

// stringToCap maps Capability string representations to their values.
var stringToCap = map[string]Capability{
	"TPM2_CAP_ALGS":            TPM2_CAP_ALGS,
	"TPM2_CAP_HANDLES":         TPM2_CAP_HANDLES,
	"TPM2_CAP_COMMANDS":        TPM2_CAP_COMMANDS,
	"TPM2_CAP_PP_COMMANDS":     TPM2_CAP_PP_COMMANDS,
	"TPM2_CAP_AUDIT_COMMANDS":  TPM2_CAP_AUDIT_COMMANDS,
	"TPM2_CAP_PCRS":            TPM2_CAP_PCRS,
	"TPM2_CAP_TPM_PROPERTIES":  TPM2_CAP_TPM_PROPERTIES,
	"TPM2_CAP_PCR_PROPERTIES":  TPM2_CAP_PCR_PROPERTIES,
	"TPM2_CAP_ECC_CURVES":      TPM2_CAP_ECC_CURVES,
	"TPM2_CAP_VENDOR_PROPERTY": TPM2_CAP_VENDOR_PROPERTY,
}

// cmdToString maps Command values to their string representations.
var cmdToString = map[Command]string{
	TPM2_CC_NV_UndefineSpaceSpecial:    "TPM2_CC_NV_UndefineSpaceSpecial",
	TPM2_CC_EvictControl:               "TPM2_CC_EvictControl",
	TPM2_CC_HierarchyControl:           "TPM2_CC_HierarchyControl",
	TPM2_CC_NV_UndefineSpace:           "TPM2_CC_NV_UndefineSpace",
	TPM2_CC_ChangeEPS:                  "TPM2_CC_ChangeEPS",
	TPM2_CC_ChangePPS:                  "TPM2_CC_ChangePPS",
	TPM2_CC_Clear:                      "TPM2_CC_Clear",
	TPM2_CC_ClearControl:               "TPM2_CC_ClearControl",
	TPM2_CC_ClockSet:                   "TPM2_CC_ClockSet",
	TPM2_CC_HierarchyChangeAuth:        "TPM2_CC_HierarchyChangeAuth",
	TPM2_CC_NV_DefineSpace:             "TPM2_CC_NV_DefineSpace",
	TPM2_CC_PCR_Allocate:               "TPM2_CC_PCR_Allocate",
	TPM2_CC_PCR_SetAuthPolicy:          "TPM2_CC_PCR_SetAuthPolicy",
	TPM2_CC_PP_Commands:                "TPM2_CC_PP_Commands",
	TPM2_CC_SetPrimaryPolicy:           "TPM2_CC_SetPrimaryPolicy",
	TPM2_CC_FieldUpgradeStart:          "TPM2_CC_FieldUpgradeStart",
	TPM2_CC_ClockRateAdjust:            "TPM2_CC_ClockRateAdjust",
	TPM2_CC_CreatePrimary:              "TPM2_CC_CreatePrimary",
	TPM2_CC_NV_GlobalWriteLock:         "TPM2_CC_NV_GlobalWriteLock",
	TPM2_CC_GetCommandAuditDigest:      "TPM2_CC_GetCommandAuditDigest",
	TPM2_CC_NV_Increment:               "TPM2_CC_NV_Increment",
	TPM2_CC_NV_SetBits:                 "TPM2_CC_NV_SetBits",
	TPM2_CC_NV_Extend:                  "TPM2_CC_NV_Extend",
	TPM2_CC_NV_Write:                   "TPM2_CC_NV_Write",
	TPM2_CC_NV_WriteLock:               "TPM2_CC_NV_WriteLock",
	TPM2_CC_DictionaryAttackLockReset:  "TPM2_CC_DictionaryAttackLockReset",
	TPM2_CC_DictionaryAttackParameters: "TPM2_CC_DictionaryAttackParameters",
	TPM2_CC_NV_ChangeAuth:              "TPM2_CC_NV_ChangeAuth",
	TPM2_CC_PCR_Event:                  "TPM2_CC_PCR_Event",
	TPM2_CC_PCR_Reset:                  "TPM2_CC_PCR_Reset",
	TPM2_CC_SequenceComplete:           "TPM2_CC_SequenceComplete",
	TPM2_CC_SetAlgorithmSet:            "TPM2_CC_SetAlgorithmSet",
	TPM2_CC_SetCommandCodeAuditStatus:  "TPM2_CC_SetCommandCodeAuditStatus",
	TPM2_CC_FieldUpgradeData:           "TPM2_CC_FieldUpgradeData",
	TPM2_CC_IncrementalSelfTest:        "TPM2_CC_IncrementalSelfTest",
	TPM2_CC_SelfTest:                   "TPM2_CC_SelfTest",
	TPM2_CC_Startup:                    "TPM2_CC_Startup",
	TPM2_CC_Shutdown:                   "TPM2_CC_Shutdown",
	TPM2_CC_StirRandom:                 "TPM2_CC_StirRandom",
	TPM2_CC_ActivateCredential:         "TPM2_CC_ActivateCredential",
	TPM2_CC_Certify:                    "TPM2_CC_Certify",
	TPM2_CC_PolicyNV:                   "TPM2_CC_PolicyNV",
	TPM2_CC_CertifyCreation:            "TPM2_CC_CertifyCreation",
	TPM2_CC_Duplicate:                  "TPM2_CC_Duplicate",
	TPM2_CC_GetTime:                    "TPM2_CC_GetTime",
	TPM2_CC_GetSessionAuditDigest:      "TPM2_CC_GetSessionAuditDigest",
	TPM2_CC_NV_Read:                    "TPM2_CC_NV_Read",
	TPM2_CC_NV_ReadLock:                "TPM2_CC_NV_ReadLock",
	TPM2_CC_ObjectChangeAuth:           "TPM2_CC_ObjectChangeAuth",
	TPM2_CC_PolicySecret:               "TPM2_CC_PolicySecret",
	TPM2_CC_Rewrap:                     "TPM2_CC_Rewrap",
	TPM2_CC_Create:                     "TPM2_CC_Create",
	TPM2_CC_ECDH_ZGen:                  "TPM2_CC_ECDH_ZGen",
	TPM2_CC_HMAC:                       "TPM2_CC_HMAC",
	TPM2_CC_Import:                     "TPM2_CC_Import",
	TPM2_CC_Load:                       "TPM2_CC_Load",
	TPM2_CC_Quote:                      "TPM2_CC_Quote",
	TPM2_CC_RSA_Decrypt:                "TPM2_CC_RSA_Decrypt",
	TPM2_CC_HMAC_Start:                 "TPM2_CC_HMAC_Start",
	TPM2_CC_SequenceUpdate:             "TPM2_CC_SequenceUpdate",
	TPM2_CC_Sign:                       "TPM2_CC_Sign",
	TPM2_CC_Unseal:                     "TPM2_CC_Unseal",
	TPM2_CC_PolicySigned:               "TPM2_CC_PolicySigned",
	TPM2_CC_ContextLoad:                "TPM2_CC_ContextLoad",
	TPM2_CC_ContextSave:                "TPM2_CC_ContextSave",
	TPM2_CC_ECDH_KeyGen:                "TPM2_CC_ECDH_KeyGen",
	TPM2_CC_EncryptDecrypt:             "TPM2_CC_EncryptDecrypt",
	TPM2_CC_FlushContext:               "TPM2_CC_FlushContext",
	TPM2_CC_LoadExternal:               "TPM2_CC_LoadExternal",
	TPM2_CC_MakeCredential:             "TPM2_CC_MakeCredential",
	TPM2_CC_NV_ReadPublic:              "TPM2_CC_NV_ReadPublic",
	TPM2_CC_PolicyAuthorize:            "TPM2_CC_PolicyAuthorize",
	TPM2_CC_PolicyAuthValue:            "TPM2_CC_PolicyAuthValue",
	TPM2_CC_PolicyCommandCode:          "TPM2_CC_PolicyCommandCode",
	TPM2_CC_PolicyCounterTimer:         "TPM2_CC_PolicyCounterTimer",
	TPM2_CC_PolicyCpHash:               "TPM2_CC_PolicyCpHash",
	TPM2_CC_PolicyLocality:             "TPM2_CC_PolicyLocality",
	TPM2_CC_PolicyNameHash:             "TPM2_CC_PolicyNameHash",
	TPM2_CC_PolicyOR:                   "TPM2_CC_PolicyOR",
	TPM2_CC_PolicyTicket:               "TPM2_CC_PolicyTicket",
	TPM2_CC_ReadPublic:                 "TPM2_CC_ReadPublic",
	TPM2_CC_RSA_Encrypt:                "TPM2_CC_RSA_Encrypt",
	TPM2_CC_StartAuthSession:           "TPM2_CC_StartAuthSession",
	TPM2_CC_VerifySignature:            "TPM2_CC_VerifySignature",
	TPM2_CC_ECC_Parameters:             "TPM2_CC_ECC_Parameters",
	TPM2_CC_FirmwareRead:               "TPM2_CC_FirmwareRead",
	TPM2_CC_GetCapability:              "TPM2_CC_GetCapability",
	TPM2_CC_GetRandom:                  "TPM2_CC_GetRandom",
	TPM2_CC_GetTestResult:              "TPM2_CC_GetTestResult",
	TPM2_CC_Hash:                       "TPM2_CC_Hash",
	TPM2_CC_PCR_Read:                   "TPM2_CC_PCR_Read",
	TPM2_CC_PolicyPCR:                  "TPM2_CC_PolicyPCR",
	TPM2_CC_PolicyRestart:              "TPM2_CC_PolicyRestart",
	TPM2_CC_ReadClock:                  "TPM2_CC_ReadClock",
	TPM2_CC_PCR_Extend:                 "TPM2_CC_PCR_Extend",
	TPM2_CC_PCR_SetAuthValue:           "TPM2_CC_PCR_SetAuthValue",
	TPM2_CC_NV_Certify:                 "TPM2_CC_NV_Certify",
	TPM2_CC_EventSequenceComplete:      "TPM2_CC_EventSequenceComplete",
	TPM2_CC_HashSequenceStart:          "TPM2_CC_HashSequenceStart",
	TPM2_CC_PolicyPhysicalPresence:     "TPM2_CC_PolicyPhysicalPresence",
	TPM2_CC_PolicyDuplicationSelect:    "TPM2_CC_PolicyDuplicationSelect",
	TPM2_CC_PolicyGetDigest:            "TPM2_CC_PolicyGetDigest",
	TPM2_CC_TestParms:                  "TPM2_CC_TestParms",
	TPM2_CC_Commit:                     "TPM2_CC_Commit",
	TPM2_CC_PolicyPassword:             "TPM2_CC_PolicyPassword",
	TPM2_CC_ZGen_2Phase:                "TPM2_CC_ZGen_2Phase",
	TPM2_CC_EC_Ephemeral:               "TPM2_CC_EC_Ephemeral",
	TPM2_CC_PolicyNvWritten:            "TPM2_CC_PolicyNvWritten",
	TPM2_CC_PolicyTemplate:             "TPM2_CC_PolicyTemplate",
	TPM2_CC_CreateLoaded:               "TPM2_CC_CreateLoaded",
	TPM2_CC_PolicyAuthorizeNV:          "TPM2_CC_PolicyAuthorizeNV",
	TPM2_CC_EncryptDecrypt2:            "TPM2_CC_EncryptDecrypt2",
	TPM2_CC_AC_GetCapability:           "TPM2_CC_AC_GetCapability",
	TPM2_CC_AC_Send:                    "TPM2_CC_AC_Send",
	TPM2_CC_Policy_AC_SendSelect:       "TPM2_CC_Policy_AC_SendSelect",
	TPM2_CC_Vendor_TCG_Test:            "TPM2_CC_Vendor_TCG_Test",
}

// stringToCmd maps Command string representations to their values.
var stringToCmd = map[string]Command{
	"TPM2_CC_NV_UndefineSpaceSpecial":    TPM2_CC_NV_UndefineSpaceSpecial,
	"TPM2_CC_EvictControl":               TPM2_CC_EvictControl,
	"TPM2_CC_HierarchyControl":           TPM2_CC_HierarchyControl,
	"TPM2_CC_NV_UndefineSpace":           TPM2_CC_NV_UndefineSpace,
	"TPM2_CC_ChangeEPS":                  TPM2_CC_ChangeEPS,
	"TPM2_CC_ChangePPS":                  TPM2_CC_ChangePPS,
	"TPM2_CC_Clear":                      TPM2_CC_Clear,
	"TPM2_CC_ClearControl":               TPM2_CC_ClearControl,
	"TPM2_CC_ClockSet":                   TPM2_CC_ClockSet,
	"TPM2_CC_HierarchyChangeAuth":        TPM2_CC_HierarchyChangeAuth,
	"TPM2_CC_NV_DefineSpace":             TPM2_CC_NV_DefineSpace,
	"TPM2_CC_PCR_Allocate":               TPM2_CC_PCR_Allocate,
	"TPM2_CC_PCR_SetAuthPolicy":          TPM2_CC_PCR_SetAuthPolicy,
	"TPM2_CC_PP_Commands":                TPM2_CC_PP_Commands,
	"TPM2_CC_SetPrimaryPolicy":           TPM2_CC_SetPrimaryPolicy,
	"TPM2_CC_FieldUpgradeStart":          TPM2_CC_FieldUpgradeStart,
	"TPM2_CC_ClockRateAdjust":            TPM2_CC_ClockRateAdjust,
	"TPM2_CC_CreatePrimary":              TPM2_CC_CreatePrimary,
	"TPM2_CC_NV_GlobalWriteLock":         TPM2_CC_NV_GlobalWriteLock,
	"TPM2_CC_GetCommandAuditDigest":      TPM2_CC_GetCommandAuditDigest,
	"TPM2_CC_NV_Increment":               TPM2_CC_NV_Increment,
	"TPM2_CC_NV_SetBits":                 TPM2_CC_NV_SetBits,
	"TPM2_CC_NV_Extend":                  TPM2_CC_NV_Extend,
	"TPM2_CC_NV_Write":                   TPM2_CC_NV_Write,
	"TPM2_CC_NV_WriteLock":               TPM2_CC_NV_WriteLock,
	"TPM2_CC_DictionaryAttackLockReset":  TPM2_CC_DictionaryAttackLockReset,
	"TPM2_CC_DictionaryAttackParameters": TPM2_CC_DictionaryAttackParameters,
	"TPM2_CC_NV_ChangeAuth":              TPM2_CC_NV_ChangeAuth,
	"TPM2_CC_PCR_Event":                  TPM2_CC_PCR_Event,
	"TPM2_CC_PCR_Reset":                  TPM2_CC_PCR_Reset,
	"TPM2_CC_SequenceComplete":           TPM2_CC_SequenceComplete,
	"TPM2_CC_SetAlgorithmSet":            TPM2_CC_SetAlgorithmSet,
	"TPM2_CC_SetCommandCodeAuditStatus":  TPM2_CC_SetCommandCodeAuditStatus,
	"TPM2_CC_FieldUpgradeData":           TPM2_CC_FieldUpgradeData,
	"TPM2_CC_IncrementalSelfTest":        TPM2_CC_IncrementalSelfTest,
	"TPM2_CC_SelfTest":                   TPM2_CC_SelfTest,
	"TPM2_CC_Startup":                    TPM2_CC_Startup,
	"TPM2_CC_Shutdown":                   TPM2_CC_Shutdown,
	"TPM2_CC_StirRandom":                 TPM2_CC_StirRandom,
	"TPM2_CC_ActivateCredential":         TPM2_CC_ActivateCredential,
	"TPM2_CC_Certify":                    TPM2_CC_Certify,
	"TPM2_CC_PolicyNV":                   TPM2_CC_PolicyNV,
	"TPM2_CC_CertifyCreation":            TPM2_CC_CertifyCreation,
	"TPM2_CC_Duplicate":                  TPM2_CC_Duplicate,
	"TPM2_CC_GetTime":                    TPM2_CC_GetTime,
	"TPM2_CC_GetSessionAuditDigest":      TPM2_CC_GetSessionAuditDigest,
	"TPM2_CC_NV_Read":                    TPM2_CC_NV_Read,
	"TPM2_CC_NV_ReadLock":                TPM2_CC_NV_ReadLock,
	"TPM2_CC_ObjectChangeAuth":           TPM2_CC_ObjectChangeAuth,
	"TPM2_CC_PolicySecret":               TPM2_CC_PolicySecret,
	"TPM2_CC_Rewrap":                     TPM2_CC_Rewrap,
	"TPM2_CC_Create":                     TPM2_CC_Create,
	"TPM2_CC_ECDH_ZGen":                  TPM2_CC_ECDH_ZGen,
	"TPM2_CC_HMAC":                       TPM2_CC_HMAC,
	"TPM2_CC_Import":                     TPM2_CC_Import,
	"TPM2_CC_Load":                       TPM2_CC_Load,
	"TPM2_CC_Quote":                      TPM2_CC_Quote,
	"TPM2_CC_RSA_Decrypt":                TPM2_CC_RSA_Decrypt,
	"TPM2_CC_HMAC_Start":                 TPM2_CC_HMAC_Start,
	"TPM2_CC_SequenceUpdate":             TPM2_CC_SequenceUpdate,
	"TPM2_CC_Sign":                       TPM2_CC_Sign,
	"TPM2_CC_Unseal":                     TPM2_CC_Unseal,
	"TPM2_CC_PolicySigned":               TPM2_CC_PolicySigned,
	"TPM2_CC_ContextLoad":                TPM2_CC_ContextLoad,
	"TPM2_CC_ContextSave":                TPM2_CC_ContextSave,
	"TPM2_CC_ECDH_KeyGen":                TPM2_CC_ECDH_KeyGen,
	"TPM2_CC_EncryptDecrypt":             TPM2_CC_EncryptDecrypt,
	"TPM2_CC_FlushContext":               TPM2_CC_FlushContext,
	"TPM2_CC_LoadExternal":               TPM2_CC_LoadExternal,
	"TPM2_CC_MakeCredential":             TPM2_CC_MakeCredential,
	"TPM2_CC_NV_ReadPublic":              TPM2_CC_NV_ReadPublic,
	"TPM2_CC_PolicyAuthorize":            TPM2_CC_PolicyAuthorize,
	"TPM2_CC_PolicyAuthValue":            TPM2_CC_PolicyAuthValue,
	"TPM2_CC_PolicyCommandCode":          TPM2_CC_PolicyCommandCode,
	"TPM2_CC_PolicyCounterTimer":         TPM2_CC_PolicyCounterTimer,
	"TPM2_CC_PolicyCpHash":               TPM2_CC_PolicyCpHash,
	"TPM2_CC_PolicyLocality":             TPM2_CC_PolicyLocality,
	"TPM2_CC_PolicyNameHash":             TPM2_CC_PolicyNameHash,
	"TPM2_CC_PolicyOR":                   TPM2_CC_PolicyOR,
	"TPM2_CC_PolicyTicket":               TPM2_CC_PolicyTicket,
	"TPM2_CC_ReadPublic":                 TPM2_CC_ReadPublic,
	"TPM2_CC_RSA_Encrypt":                TPM2_CC_RSA_Encrypt,
	"TPM2_CC_StartAuthSession":           TPM2_CC_StartAuthSession,
	"TPM2_CC_VerifySignature":            TPM2_CC_VerifySignature,
	"TPM2_CC_ECC_Parameters":             TPM2_CC_ECC_Parameters,
	"TPM2_CC_FirmwareRead":               TPM2_CC_FirmwareRead,
	"TPM2_CC_GetCapability":              TPM2_CC_GetCapability,
	"TPM2_CC_GetRandom":                  TPM2_CC_GetRandom,
	"TPM2_CC_GetTestResult":              TPM2_CC_GetTestResult,
	"TPM2_CC_Hash":                       TPM2_CC_Hash,
	"TPM2_CC_PCR_Read":                   TPM2_CC_PCR_Read,
	"TPM2_CC_PolicyPCR":                  TPM2_CC_PolicyPCR,
	"TPM2_CC_PolicyRestart":              TPM2_CC_PolicyRestart,
	"TPM2_CC_ReadClock":                  TPM2_CC_ReadClock,
	"TPM2_CC_PCR_Extend":                 TPM2_CC_PCR_Extend,
	"TPM2_CC_PCR_SetAuthValue":           TPM2_CC_PCR_SetAuthValue,
	"TPM2_CC_NV_Certify":                 TPM2_CC_NV_Certify,
	"TPM2_CC_EventSequenceComplete":      TPM2_CC_EventSequenceComplete,
	"TPM2_CC_HashSequenceStart":          TPM2_CC_HashSequenceStart,
	"TPM2_CC_PolicyPhysicalPresence":     TPM2_CC_PolicyPhysicalPresence,
	"TPM2_CC_PolicyDuplicationSelect":    TPM2_CC_PolicyDuplicationSelect,
	"TPM2_CC_PolicyGetDigest":            TPM2_CC_PolicyGetDigest,
	"TPM2_CC_TestParms":                  TPM2_CC_TestParms,
	"TPM2_CC_Commit":                     TPM2_CC_Commit,
	"TPM2_CC_PolicyPassword":             TPM2_CC_PolicyPassword,
	"TPM2_CC_ZGen_2Phase":                TPM2_CC_ZGen_2Phase,
	"TPM2_CC_EC_Ephemeral":               TPM2_CC_EC_Ephemeral,
	"TPM2_CC_PolicyNvWritten":            TPM2_CC_PolicyNvWritten,
	"TPM2_CC_PolicyTemplate":             TPM2_CC_PolicyTemplate,
	"TPM2_CC_CreateLoaded":               TPM2_CC_CreateLoaded,
	"TPM2_CC_PolicyAuthorizeNV":          TPM2_CC_PolicyAuthorizeNV,
	"TPM2_CC_EncryptDecrypt2":            TPM2_CC_EncryptDecrypt2,
	"TPM2_CC_AC_GetCapability":           TPM2_CC_AC_GetCapability,
	"TPM2_CC_AC_Send":                    TPM2_CC_AC_Send,
	"TPM2_CC_Policy_AC_SendSelect":       TPM2_CC_Policy_AC_SendSelect,
	"TPM2_CC_Vendor_TCG_Test":            TPM2_CC_Vendor_TCG_Test,
}

// curveToString maps EllipticCurve values to their string representations.
var curveToString = map[EllipticCurve]string{
	TPM2_ECC_NONE:      "TPM2_ECC_NONE",
	TPM2_ECC_NIST_P192: "TPM2_ECC_NIST_P192",
	TPM2_ECC_NIST_P224: "TPM2_ECC_NIST_P224",
	TPM2_ECC_NIST_P256: "TPM2_ECC_NIST_P256",
	TPM2_ECC_NIST_P384: "TPM2_ECC_NIST_P384",
	TPM2_ECC_NIST_P521: "TPM2_ECC_NIST_P521",
	TPM2_ECC_BN_P256:   "TPM2_ECC_BN_P256",
	TPM2_ECC_BN_P638:   "TPM2_ECC_BN_P638",
	TPM2_ECC_SM2_P256:  "TPM2_ECC_SM2_P256",
}

// stringToCurve maps EllipticCurve string representations to their values.
var stringToCurve = map[string]EllipticCurve{
	"TPM2_ECC_NONE":      TPM2_ECC_NONE,
	"TPM2_ECC_NIST_P192": TPM2_ECC_NIST_P192,
	"TPM2_ECC_NIST_P224": TPM2_ECC_NIST_P224,
	"TPM2_ECC_NIST_P256": TPM2_ECC_NIST_P256,
	"TPM2_ECC_NIST_P384": TPM2_ECC_NIST_P384,
	"TPM2_ECC_NIST_P521": TPM2_ECC_NIST_P521,
	"TPM2_ECC_BN_P256":   TPM2_ECC_BN_P256,
	"TPM2_ECC_BN_P638":   TPM2_ECC_BN_P638,
	"TPM2_ECC_SM2_P256":  TPM2_ECC_SM2_P256,
}

// handleTypeToString maps HandleType values to their string representations.
var handleTypeToString = map[HandleType]string{
	TPM2_HT_PCR:            "TPM2_HT_PCR",
	TPM2_HT_NV_INDEX:       "TPM2_HT_NV_INDEX",
	TPM2_HT_HMAC_SESSION:   "TPM2_HT_HMAC_SESSION",
	TPM2_HT_POLICY_SESSION: "TPM2_HT_POLICY_SESSION",
	TPM2_HT_PERMANENT:      "TPM2_HT_PERMANENT",
	TPM2_HT_TRANSIENT:      "TPM2_HT_TRANSIENT",
	TPM2_HT_PERSISTENT:     "TPM2_HT_PERSISTENT",
}

// stringToHandleType maps HandleType string representations to their values.
var stringToHandleType = map[string]HandleType{
	"TPM2_HT_PCR":            TPM2_HT_PCR,
	"TPM2_HT_NV_INDEX":       TPM2_HT_NV_INDEX,
	"TPM2_HT_HMAC_SESSION":   TPM2_HT_HMAC_SESSION,
	"TPM2_HT_POLICY_SESSION": TPM2_HT_POLICY_SESSION,
	"TPM2_HT_PERMANENT":      TPM2_HT_PERMANENT,
	"TPM2_HT_TRANSIENT":      TPM2_HT_TRANSIENT,
	"TPM2_HT_PERSISTENT":     TPM2_HT_PERSISTENT,
}

// objAttrToString maps ObjectAttribute values to their string representations.
var objAttrToString = map[ObjectAttribute]string{
	TPMA_OBJECT_FIXEDTPM:             "TPMA_OBJECT_FIXEDTPM",
	TPMA_OBJECT_STCLEAR:              "TPMA_OBJECT_STCLEAR",
	TPMA_OBJECT_FIXEDPARENT:          "TPMA_OBJECT_FIXEDPARENT",
	TPMA_OBJECT_SENSITIVEDATAORIGIN:  "TPMA_OBJECT_SENSITIVEDATAORIGIN",
	TPMA_OBJECT_USERWITHAUTH:         "TPMA_OBJECT_USERWITHAUTH",
	TPMA_OBJECT_ADMINWITHPOLICY:      "TPMA_OBJECT_ADMINWITHPOLICY",
	TPMA_OBJECT_NODA:                 "TPMA_OBJECT_NODA",
	TPMA_OBJECT_ENCRYPTEDDUPLICATION: "TPMA_OBJECT_ENCRYPTEDDUPLICATION",
	TPMA_OBJECT_RESTRICTED:           "TPMA_OBJECT_RESTRICTED",
	TPMA_OBJECT_DECRYPT:              "TPMA_OBJECT_DECRYPT",
	TPMA_OBJECT_SIGN_ENCRYPT:         "TPMA_OBJECT_SIGN_ENCRYPT",
}

// stringToObjAttr maps ObjectAttribute string representations to their values.
var stringToObjAttr = map[string]ObjectAttribute{
	"TPMA_OBJECT_FIXEDTPM":             TPMA_OBJECT_FIXEDTPM,
	"TPMA_OBJECT_STCLEAR":              TPMA_OBJECT_STCLEAR,
	"TPMA_OBJECT_FIXEDPARENT":          TPMA_OBJECT_FIXEDPARENT,
	"TPMA_OBJECT_SENSITIVEDATAORIGIN":  TPMA_OBJECT_SENSITIVEDATAORIGIN,
	"TPMA_OBJECT_USERWITHAUTH":         TPMA_OBJECT_USERWITHAUTH,
	"TPMA_OBJECT_ADMINWITHPOLICY":      TPMA_OBJECT_ADMINWITHPOLICY,
	"TPMA_OBJECT_NODA":                 TPMA_OBJECT_NODA,
	"TPMA_OBJECT_ENCRYPTEDDUPLICATION": TPMA_OBJECT_ENCRYPTEDDUPLICATION,
	"TPMA_OBJECT_RESTRICTED":           TPMA_OBJECT_RESTRICTED,
	"TPMA_OBJECT_DECRYPT":              TPMA_OBJECT_DECRYPT,
	"TPMA_OBJECT_SIGN_ENCRYPT":         TPMA_OBJECT_SIGN_ENCRYPT,
}

// String returns a string representation of a value.
func (a Algorithm) String() string {
	s, ok := algToString[a]
	if !ok {
		return "UNKNOWN ALGORITHM VALUE"
	}

	return s
}

// MarshalJSON returns the JSON-encoding of a value.
func (a Algorithm) MarshalJSON() ([]byte, error) {
	s, ok := algToString[a]
	if !ok {
		return nil, fmt.Errorf("invalid algorithm value: %d", a)
	}

	return json.Marshal(s)
}

// UnmarshalJSON parses a JSON-encoded value and stores the result in the
// object.
func (a *Algorithm) UnmarshalJSON(b []byte) error {
	var s string

	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}

	v, ok := stringToAlg[s]
	if !ok {
		return fmt.Errorf("invalid algorithm value: %s", s)
	}

	*a = v

	return nil
}

// String returns a string representation of a value.
func (a AlgorithmAttribute) String() string {
	s, ok := algAttrToString[a]
	if !ok {
		return "UNKNOWN ALGORITHM ATTRIBUTE VALUE"
	}

	return s
}

// MarshalJSON returns the JSON-encoding of a value.
func (a AlgorithmAttribute) MarshalJSON() ([]byte, error) {
	s, ok := algAttrToString[a]
	if !ok {
		return nil, fmt.Errorf("invalid algorithm attribute value: %d", a)
	}

	return json.Marshal(s)
}

// UnmarshalJSON parses a JSON-encoded value and stores the result in the
// object.
func (a *AlgorithmAttribute) UnmarshalJSON(b []byte) error {
	var s string

	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}

	v, ok := stringToAlgAttr[s]
	if !ok {
		return fmt.Errorf("invalid algorithm attribute value: %s", s)
	}

	*a = v

	return nil
}

// String returns a string representation of a value.
func (c Capability) String() string {
	s, ok := capToString[c]
	if !ok {
		return "UNKNOWN CAPABILITY VALUE"
	}

	return s
}

// MarshalJSON returns the JSON-encoding of a value.
func (c Capability) MarshalJSON() ([]byte, error) {
	s, ok := capToString[c]
	if !ok {
		return nil, fmt.Errorf("invalid capability value: %d", c)
	}

	return json.Marshal(s)
}

// UnmarshalJSON parses a JSON-encoded value and stores the result in the
// object.
func (c *Capability) UnmarshalJSON(b []byte) error {
	var s string

	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}

	v, ok := stringToCap[s]
	if !ok {
		return fmt.Errorf("invalid capability value: %s", s)
	}

	*c = v

	return nil
}

// String returns a string representation of a value.
func (c Command) String() string {
	s, ok := cmdToString[c]
	if !ok {
		return "UNKNOWN COMMAND VALUE"
	}

	return s
}

// MarshalJSON returns the JSON-encoding of a value.
func (c Command) MarshalJSON() ([]byte, error) {
	s, ok := cmdToString[c]
	if !ok {
		return nil, fmt.Errorf("invalid command value: %d", c)
	}

	return json.Marshal(s)
}

// UnmarshalJSON parses a JSON-encoded value and stores the result in the
// object.
func (c *Command) UnmarshalJSON(b []byte) error {
	var s string

	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}

	v, ok := stringToCmd[s]
	if !ok {
		return fmt.Errorf("invalid command value: %s", s)
	}

	*c = v

	return nil
}

// String returns a string representation of a value.
func (c EllipticCurve) String() string {
	s, ok := curveToString[c]
	if !ok {
		return "UNKNOWN ELLIPTIC CURVE VALUE"
	}

	return s
}

// MarshalJSON returns the JSON-encoding of a value.
func (c EllipticCurve) MarshalJSON() ([]byte, error) {
	s, ok := curveToString[c]
	if !ok {
		return nil, fmt.Errorf("invalid elliptic curve value: %d", c)
	}

	return json.Marshal(s)
}

// UnmarshalJSON parses a JSON-encoded value and stores the result in the
// object.
func (c *EllipticCurve) UnmarshalJSON(b []byte) error {
	var s string

	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}

	v, ok := stringToCurve[s]
	if !ok {
		return fmt.Errorf("invalid elliptic curve value: %s", s)
	}

	*c = v

	return nil
}

// HandleType returns the type of a handle.
func (h Handle) HandleType() HandleType {
	return HandleType((uint32(h) & TPM2_HR_RANGE_MASK) >> TPM2_HR_SHIFT)
}

// First returns the first possible handle value of the type.
func (t HandleType) First() Handle {
	return Handle(uint32(t) << TPM2_HR_SHIFT)
}

// String returns a string representation of a value.
func (t HandleType) String() string {
	s, ok := handleTypeToString[t]
	if !ok {
		return "UNKNOWN HANDLE TYPE VALUE"
	}

	return s
}

// MarshalJSON returns the JSON-encoding of a value.
func (t HandleType) MarshalJSON() ([]byte, error) {
	s, ok := handleTypeToString[t]
	if !ok {
		return nil, fmt.Errorf("invalid handle type value: %d", t)
	}

	return json.Marshal(s)
}

// UnmarshalJSON parses a JSON-encoded value and stores the result in the
// object.
func (t *HandleType) UnmarshalJSON(b []byte) error {
	var s string

	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}

	v, ok := stringToHandleType[s]
	if !ok {
		return fmt.Errorf("invalid handle type value: %s", s)
	}

	*t = v

	return nil
}

// String returns a string representation of a value.
func (a ObjectAttribute) String() string {
	s, ok := objAttrToString[a]
	if !ok {
		return "UNKNOWN OBJECT ATTRIBUTE VALUE"
	}

	return s
}

// MarshalJSON returns the JSON-encoding of a value.
func (a ObjectAttribute) MarshalJSON() ([]byte, error) {
	s, ok := objAttrToString[a]
	if !ok {
		return nil, fmt.Errorf("invalid object attribute value: %d", a)
	}

	return json.Marshal(s)
}

// UnmarshalJSON parses a JSON-encoded value and stores the result in the
// object.
func (a *ObjectAttribute) UnmarshalJSON(b []byte) error {
	var s string

	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}

	v, ok := stringToObjAttr[s]
	if !ok {
		return fmt.Errorf("invalid object attribute value: %s", s)
	}

	*a = v

	return nil
}
