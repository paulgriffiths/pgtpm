package pgtpm

import (
	"math/big"

	"github.com/google/go-tpm/tpm2"
)

// PublicTemplate marshals/unmarshals to/from the JSON-encoding of a
// tpm2.Public object.
type PublicTemplate struct {
	Type                Algorithm         `json:"type"`
	NameAlg             Algorithm         `json:"name_alg"`
	Attributes          []ObjectAttribute `json:"attributes,omitempty"`
	AuthPolicy          []byte            `json:"auth_policy,omitempty"`
	RSAParameters       *RSAParams        `json:"rsa,omitempty"`
	ECCParameters       *ECCParams        `json:"ecc,omitempty"`
	SymCipherParameters *SymCipherParams  `json:"sym_cipher,omitempty"`
	KeyedHashParameters *KeyedHashParams  `json:"keyed_hash,omitempty"`
}

// RSAParams represents parameters of an RSA key pair.
type RSAParams struct {
	Symmetric *SymScheme `json:"symmetric,omitempty"`
	Sign      *SigScheme `json:"scheme,omitempty"`
	KeyBits   uint16     `json:"key_bits"`
	Exponent  uint32     `json:"exponent"`
	Modulus   *big.Int   `json:"modulus,omitempty"`
}

// ECCParams represents parameters of an ECC key pair.
type ECCParams struct {
	Symmetric *SymScheme    `json:"symmetric,omitempty"`
	Sign      *SigScheme    `json:"scheme,omitempty"`
	CurveID   EllipticCurve `json:"elliptic_curve"`
	KDF       *KDFScheme    `json:"kdf,omitempty"`
	Point     *ECPoint      `json:"point,omitempty"`
}

// SymCipherParams represents parameters of a symmetric cipher TPM object.
type SymCipherParams struct {
	Symmetric *SymScheme `json:"symmetric,omitempty"`
}

// KeyedHashParams represents parameters of a keyed hash TPM object.
type KeyedHashParams struct {
	Alg  Algorithm `json:"algorithm"`
	Hash Algorithm `json:"hash"`
	KDF  Algorithm `json:"kdf"`
}

// SymScheme represents a symmetric encryption scheme.
type SymScheme struct {
	Alg     Algorithm `json:"algorithm"`
	KeyBits uint16    `json:"key_bits"`
	Mode    Algorithm `json:"mode"`
}

// SigScheme represents a signing scheme.
type SigScheme struct {
	Alg   Algorithm `json:"algorithm"`
	Hash  Algorithm `json:"hash"`
	Count uint32    `json:"count"`
}

// KDFScheme represents a key derivation function scheme.
type KDFScheme struct {
	Alg  Algorithm `json:"algorithm"`
	Hash Algorithm `json:"hash"`
}

// ECPoint represents ECC coordinates for a point.
type ECPoint struct {
	X *big.Int `json:"x,omitempty"`
	Y *big.Int `json:"y,omitempty"`
}

// ToPublic converts to a corresponding tpm2 object.
func (t PublicTemplate) ToPublic() tpm2.Public {
	rv := tpm2.Public{
		Type:       tpm2.Algorithm(t.Type),
		NameAlg:    tpm2.Algorithm(t.NameAlg),
		AuthPolicy: t.AuthPolicy,
	}

	for _, p := range t.Attributes {
		rv.Attributes |= tpm2.KeyProp(p)
	}

	if t.RSAParameters != nil {
		rv.RSAParameters = t.RSAParameters.ToPublic()
	}

	if t.ECCParameters != nil {
		rv.ECCParameters = t.ECCParameters.ToPublic()
	}

	if t.SymCipherParameters != nil {
		rv.SymCipherParameters = t.SymCipherParameters.ToPublic()
	}

	if t.KeyedHashParameters != nil {
		rv.KeyedHashParameters = t.KeyedHashParameters.ToPublic()
	}

	return rv
}

// ToPublic converts to a corresponding tpm2 object.
func (p RSAParams) ToPublic() *tpm2.RSAParams {
	rv := &tpm2.RSAParams{
		KeyBits:     p.KeyBits,
		ExponentRaw: p.Exponent,
	}

	if p.Symmetric != nil {
		rv.Symmetric = p.Symmetric.ToPublic()
	}

	if p.Sign != nil {
		rv.Sign = p.Sign.ToPublic()
	}

	// For endorsement key templates, the RSA unique value is a slice of zero
	// octets of equal size to the number of key bits. To allow zero (or a
	// smaller number) to be specified in the template without explicitly
	// writing all the zero bytes, if a value is specified we make it a fixed
	// number of bytes based on the key bits.
	if p.Modulus != nil {
		rv.ModulusRaw = bigIntToFixedSizeBytes(p.Modulus, int(p.KeyBits/8))
	}

	return rv
}

// ToPublic converts to a corresponding tpm2 object.
func (p ECCParams) ToPublic() *tpm2.ECCParams {
	rv := &tpm2.ECCParams{
		CurveID: tpm2.EllipticCurve(p.CurveID),
	}

	if p.Symmetric != nil {
		rv.Symmetric = p.Symmetric.ToPublic()
	}

	if p.Sign != nil {
		rv.Sign = p.Sign.ToPublic()
	}

	if p.KDF != nil {
		rv.KDF = p.KDF.ToPublic()
	}

	if p.Point != nil {
		rv.Point = p.Point.ToPublic(tpm2.EllipticCurve(p.CurveID))
	}

	return rv
}

// ToPublic converts to a corresponding tpm2 object.
func (p SymCipherParams) ToPublic() *tpm2.SymCipherParams {
	rv := &tpm2.SymCipherParams{}

	if p.Symmetric != nil {
		rv.Symmetric = p.Symmetric.ToPublic()
	}

	return rv
}

// ToPublic converts to a corresponding tpm2 object.
func (p KeyedHashParams) ToPublic() *tpm2.KeyedHashParams {
	return &tpm2.KeyedHashParams{
		Alg:  tpm2.Algorithm(p.Alg),
		Hash: tpm2.Algorithm(p.Hash),
		KDF:  tpm2.Algorithm(p.KDF),
	}
}

// ToPublic converts to a corresponding tpm2 object.
func (s SymScheme) ToPublic() *tpm2.SymScheme {
	return &tpm2.SymScheme{
		Alg:     tpm2.Algorithm(s.Alg),
		KeyBits: s.KeyBits,
		Mode:    tpm2.Algorithm(s.Mode),
	}
}

// ToPublic converts to a corresponding tpm2 object.
func (s SigScheme) ToPublic() *tpm2.SigScheme {
	return &tpm2.SigScheme{
		Alg:   tpm2.Algorithm(s.Alg),
		Hash:  tpm2.Algorithm(s.Hash),
		Count: s.Count,
	}
}

// ToPublic converts to a corresponding tpm2 object.
func (s KDFScheme) ToPublic() *tpm2.KDFScheme {
	return &tpm2.KDFScheme{
		Alg:  tpm2.Algorithm(s.Alg),
		Hash: tpm2.Algorithm(s.Hash),
	}
}

// ToPublic converts to a corresponding tpm2 object.
func (s ECPoint) ToPublic(id tpm2.EllipticCurve) tpm2.ECPoint {
	var rv tpm2.ECPoint

	// For endorsement key templates, the ECC unique value is a slice of zero
	// octets of equal size to the number of key bits. To allow zero (or a
	// smaller number) to be specified in the template without explicitly
	// writing all the zero bytes, if a value is specified we make it a fixed
	// number of bytes depending on the curve type.
	var size int
	switch id {
	case tpm2.CurveNISTP192:
		size = 24

	case tpm2.CurveNISTP224:
		size = 28

	case tpm2.CurveNISTP256, tpm2.CurveBNP256, tpm2.CurveSM2P256:
		size = 32

	case tpm2.CurveNISTP384:
		size = 48

	case tpm2.CurveNISTP521:
		size = 66

	case tpm2.CurveBNP638:
		size = 80
	}

	if s.X != nil && size != 0 {
		rv.XRaw = bigIntToFixedSizeBytes(s.X, size)
	}

	if s.Y != nil && size != 0 {
		rv.YRaw = bigIntToFixedSizeBytes(s.Y, size)
	}

	return rv
}

func bigIntToFixedSizeBytes(n *big.Int, size int) []byte {
	b := make([]byte, size)
	l := len(n.Bytes())

	if l >= size {
		copy(b, n.Bytes())
	} else {
		copy(b[size-l:size], n.Bytes())
	}

	return b
}
