package pgtpm

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

// PrivateKey represents a signing private key in a TPM.
type PrivateKey struct {
	rw     io.ReadWriter
	handle tpmutil.Handle
	pubKey crypto.PublicKey
	scheme *tpm2.SigScheme
}

type ecdsaSignature struct {
	R *big.Int
	S *big.Int
}

// Public returns the public key corresponding to the opaque,
// private key.
func (k *PrivateKey) Public() crypto.PublicKey {
	return k.pubKey
}

// Sign signs digest with the private key.
func (k *PrivateKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	var scheme tpm2.SigScheme

	// Use the signature algorithm specified by the key, or choose an
	// appropriate default.
	if k.scheme == nil || k.scheme.Alg == tpm2.AlgNull {
		switch t := k.pubKey.(type) {
		case *rsa.PublicKey:
			scheme.Alg = tpm2.AlgRSASSA

		case *ecdsa.PublicKey:
			scheme.Alg = tpm2.AlgECDSA

		default:
			return nil, fmt.Errorf("unexpected public key type: %v", t)
		}
	} else {
		scheme.Alg = k.scheme.Alg
	}

	switch opts.HashFunc() {
	case 0:
		return nil, errors.New("digest was not hashed")

	case crypto.SHA1:
		scheme.Hash = tpm2.AlgSHA1

	case crypto.SHA256:
		scheme.Hash = tpm2.AlgSHA256

	case crypto.SHA384:
		scheme.Hash = tpm2.AlgSHA384

	case crypto.SHA512:
		scheme.Hash = tpm2.AlgSHA512

	default:
		return nil, errors.New("unsupported hash function")
	}

	sig, err := tpm2.Sign(k.rw, k.handle, "", digest, &scheme)
	if err != nil {
		return nil, err
	}

	switch {
	case sig.RSA != nil:
		return sig.RSA.Signature, nil

	case sig.ECC != nil:
		tmp := ecdsaSignature{
			R: sig.ECC.R,
			S: sig.ECC.S,
		}

		der, err := asn1.Marshal(tmp)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal ASN.1: %v", err)
		}

		return der, nil
	}

	return nil, errors.New("some error has occurred")
}

// PrivateKeyFromActiveHandle returns a private key object representing the key
// referred to by the specified handle. The caller is responsible for ensuring
// that the handle for the key is not changed, and the io.ReadWriter is not
// closed, until the returned key will no longer be used.
func PrivateKeyFromActiveHandle(rw io.ReadWriter, handle tpmutil.Handle) (crypto.Signer, error) {
	pub, _, _, err := tpm2.ReadPublic(rw, handle)
	if err != nil {
		return nil, fmt.Errorf("couldn't read public area from TPM: %v", err)
	}

	pubKey, err := pub.Key()
	if err != nil {
		return nil, fmt.Errorf("couldn't get public key from public area: %v", err)
	}

	var scheme *tpm2.SigScheme

	switch {
	case pub.RSAParameters != nil:
		scheme = pub.RSAParameters.Sign

	case pub.ECCParameters != nil:
		scheme = pub.ECCParameters.Sign

	default:
		return nil, errors.New("not an RSA or ECC key")
	}

	return &PrivateKey{
		rw:     rw,
		handle: handle,
		pubKey: pubKey,
		scheme: scheme,
	}, nil
}
