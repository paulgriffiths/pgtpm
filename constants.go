package pgtpm

import (
	"encoding/json"
	"fmt"
)

// Algorithm is a TPM2_ALG_ID Constant.
type Algorithm uint32

// AlgorithmAttribute is a UINT32 TPMA_ALGORITHM Bit Constant.
type AlgorithmAttribute uint32

// Capability is a UINT32 TPM2_CAP Constant.
type Capability uint32

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
