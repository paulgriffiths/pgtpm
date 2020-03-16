package pgtpm

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
	"io"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

const (
	labelIdentity  = "IDENTITY"
	labelIntegrity = "INTEGRITY"
	labelStorage   = "STORAGE"
	sizeFieldLen   = 2
)

// MakeCredential makes a credential for the object with the public area
// akPublic, to be activated by the object with the public area ekPublic.
// The credential blob and the encrypted seed are returned.
func MakeCredential(cred, ekPublic, akPublic []byte) ([]byte, []byte, error) {
	// Decode endorsement and attestation key public areas.
	ekPub, err := tpm2.DecodePublic(ekPublic)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode endorsement key public area: %v", err)
	}

	akPub, err := tpm2.DecodePublic(akPublic)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode attestation key public area: %v", err)
	}

	// Generate seed and EK-encrypted seed.
	seed, encSeed, err := generateSeed(ekPub)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate seed: %v", err)
	}

	// Generate credential blob.
	blob, err := generateCredentialBlob(ekPub, akPub, cred, seed)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate credential blob: %v", err)
	}

	return blob, encSeed, nil
}

// generateSeed generates a seed value and encrypts it using the public key
// in the specified public area per TPM Library spec Section 24.
func generateSeed(ekPub tpm2.Public) ([]byte, []byte, error) {
	// Extract the name algorithm from the public area.
	newHash, err := nameAlgHashFromPublic(ekPub)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to determine EK name hash algorithm: %v", err)
	}

	// Generate a random seed value. Per TPM Library spec Appendix B.10.3, for
	// RSA keys the seed size will be the size of a digest produced by the OAEP
	// hash algorithm of the endorsement key, and per TPM Library Spec Appendix
	// C.6.1, for ECC keys the seed size will be the size of a digest produced
	// by the name algorithm for the endorsement key. In both cases, this
	// equates to the size of the digest of the EK's name algorithm, so we
	// generate a random seed of that size.
	h := newHash()
	seedSize := h.Size()
	seed := make([]byte, seedSize)
	if n, err := io.ReadFull(rand.Reader, seed); err != nil {
		return nil, nil, fmt.Errorf("failed to generate random bytes: %v", err)
	} else if n != seedSize {
		return nil, nil, fmt.Errorf("generated %d random bytes, expected %d", n, seedSize)
	}

	// Encrypt the seed according to the type of the EK public key.
	pubKey, err := ekPub.Key()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to extract EK public key: %v", err)
	}

	var encSeed []byte

	switch t := pubKey.(type) {
	case *rsa.PublicKey:

		// Per TPM Library spec Appendix B.10.4, the seed value will be OAEP
		// encrypted to the EK public key using "IDENTITY" as the label
		// (including the terminaing null octet per Appendix B.4.)
		encSeed, err = rsa.EncryptOAEP(h, rand.Reader, t, seed, append([]byte(labelIdentity), 0))
		if err != nil {
			return nil, nil, fmt.Errorf("failed to RSA encrypt: %v", err)
		}

	case *ecdsa.PublicKey:

		// Per TPM Library spec Appendix C.6.4, the One-Pass Diffie-Hellman,
		// C(1, 1, ECC CDH) method from SP800-56A shall be used.
		return nil, nil, fmt.Errorf("ECC keys not yet supported for seed encryption")

	default:
		return nil, nil, fmt.Errorf("unsupported public key type: %v", t)
	}

	return seed, encSeed, nil
}

// generateCredentialBlob generates an encrypted credential and HMAC per
// TPM Library spec Section 24.
func generateCredentialBlob(ekPub, akPub tpm2.Public, cred, seed []byte) ([]byte, error) {
	// Compute AK name.
	name, err := computeName(akPub)
	if err != nil {
		return nil, err
	}

	// Extract the name algorithm from the public area.
	newHash, err := nameAlgHashFromPublic(ekPub)
	if err != nil {
		return nil, fmt.Errorf("failed to determine EK name hash algorithm: %v", err)
	}

	// Encrypt credential.
	encIdentity, err := encryptCredential(ekPub, newHash, cred, seed, name)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt credential value: %v", err)
	}

	// Compute the HMAC key. Per TPM Library spec Section 24.5, the number of
	// bytes in the key should be equal to the size of the digest produced
	// by the hash algorithm used.
	macKey, err := KDFa(newHash, seed, labelIntegrity, nil, newHash().Size())
	if err != nil {
		return nil, fmt.Errorf("failed to derive integrity key: %v", err)
	}

	// Compute the HMAC
	mac := hmac.New(newHash, macKey)
	mac.Write(encIdentity)
	mac.Write(name)
	macSum := mac.Sum(nil)

	// Create and return the credential blob.
	return tpmutil.Pack(tpmutil.U16Bytes(macSum), encIdentity)
}

// encryptCredential encrypts a credential using the appropriate symmetric
// algorithm specified in a public area.
func encryptCredential(pub tpm2.Public, h func() hash.Hash, cred, seed, name []byte) ([]byte, error) {
	// Extract symmetric encryption scheme from public area.
	var sym *tpm2.SymScheme

	switch {
	case pub.RSAParameters != nil && pub.RSAParameters.Symmetric != nil:
		sym = pub.RSAParameters.Symmetric

	case pub.ECCParameters != nil && pub.ECCParameters.Symmetric != nil:
		sym = pub.ECCParameters.Symmetric

	default:
		return nil, fmt.Errorf("failed to identify symmetric algorithm")
	}

	// Generate symmetric key and create block cipher.
	var cphr cipher.Block

	switch Algorithm(sym.Alg) {
	case TPM2_ALG_AES:
		symKey, err := KDFa(h, seed, labelStorage, name, aes.BlockSize)
		if err != nil {
			return nil, fmt.Errorf("failed to derive storage key: %v", err)
		}

		cphr, err = aes.NewCipher(symKey)
		if err != nil {
			return nil, fmt.Errorf("couldn't create new AES cipher: %v", err)
		}

	default:
		return nil, fmt.Errorf("unsupported symmetric algorithm: %s", Algorithm(sym.Alg).String())
	}

	// Encrypt credential.
	cred, err := tpmutil.Pack(tpmutil.U16Bytes(cred))
	if err != nil {
		return nil, err
	}

	enc := make([]byte, len(cred))
	cipher.NewCFBEncrypter(cphr, make([]byte, cphr.BlockSize())).XORKeyStream(enc, cred)

	return enc, nil
}

// nameAlgHashFromPublic extracts the name algorithm from a public area and
// returns a function to generate a new hash.Hash implementing that algorithm.
func nameAlgHashFromPublic(pub tpm2.Public) (func() hash.Hash, error) {
	switch Algorithm(pub.NameAlg) {
	case TPM2_ALG_SHA1:
		return sha1.New, nil

	case TPM2_ALG_SHA256:
		return sha256.New, nil

	case TPM2_ALG_SHA384:
		return sha512.New384, nil

	case TPM2_ALG_SHA512:
		return sha512.New, nil
	}

	return nil, fmt.Errorf("unsupported hash algorithm: %s", Algorithm(pub.NameAlg).String())
}

// computeName computes and encodes the name of a public area, without the
// leading size field.
func computeName(pub tpm2.Public) ([]byte, error) {
	name, err := pub.Name()
	if err != nil {
		return nil, fmt.Errorf("failed to compute public area name: %v", err)
	}

	nameBytes, err := name.Encode()
	if err != nil {
		return nil, fmt.Errorf("failed to encode public area name: %v", err)
	}

	return nameBytes[sizeFieldLen:], nil
}
