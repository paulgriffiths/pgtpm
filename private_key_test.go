package pgtpm_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/asn1"
	"hash"
	"math/big"
	"testing"

	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2"

	"github.com/paulgriffiths/pgtpm"
)

func TestPrivateKeyFromActiveHandleRSASign(t *testing.T) {
	var parentPub = tpm2.Public{
		Type:       tpm2.AlgRSA,
		NameAlg:    tpm2.AlgSHA256,
		Attributes: tpm2.FlagStorageDefault,
		RSAParameters: &tpm2.RSAParams{
			Symmetric: &tpm2.SymScheme{
				Alg:     tpm2.AlgAES,
				KeyBits: 128,
				Mode:    tpm2.AlgCFB,
			},
			KeyBits: 2048,
		},
	}

	var testcases = []struct {
		name     string
		public   tpm2.Public
		hash     crypto.Hash
		hashFunc func() hash.Hash
	}{
		{
			name: "RSA/NULL/NULL/SHA1",
			public: tpm2.Public{
				Type:       tpm2.AlgRSA,
				NameAlg:    tpm2.AlgSHA256,
				Attributes: tpm2.FlagSignerDefault & ^tpm2.FlagRestricted,
				RSAParameters: &tpm2.RSAParams{
					KeyBits: 2048,
				},
			},
			hash:     crypto.SHA1,
			hashFunc: sha1.New,
		},
		{
			name: "RSA/RSASSA/SHA1/SHA1",
			public: tpm2.Public{
				Type:       tpm2.AlgRSA,
				NameAlg:    tpm2.AlgSHA256,
				Attributes: tpm2.FlagSignerDefault & ^tpm2.FlagRestricted,
				RSAParameters: &tpm2.RSAParams{
					Sign: &tpm2.SigScheme{
						Alg:  tpm2.AlgRSASSA,
						Hash: tpm2.AlgSHA1,
					},
					KeyBits: 2048,
				},
			},
			hash:     crypto.SHA1,
			hashFunc: sha1.New,
		},
		{
			name: "RSA/NULL/NULL/SHA256",
			public: tpm2.Public{
				Type:       tpm2.AlgRSA,
				NameAlg:    tpm2.AlgSHA256,
				Attributes: tpm2.FlagSignerDefault & ^tpm2.FlagRestricted,
				RSAParameters: &tpm2.RSAParams{
					KeyBits: 2048,
				},
			},
			hash:     crypto.SHA256,
			hashFunc: sha256.New,
		},
		{
			name: "RSA/RSASSA/SHA256/SHA256",
			public: tpm2.Public{
				Type:       tpm2.AlgRSA,
				NameAlg:    tpm2.AlgSHA256,
				Attributes: tpm2.FlagSignerDefault & ^tpm2.FlagRestricted,
				RSAParameters: &tpm2.RSAParams{
					Sign: &tpm2.SigScheme{
						Alg:  tpm2.AlgRSASSA,
						Hash: tpm2.AlgSHA256,
					},
					KeyBits: 2048,
				},
			},
			hash:     crypto.SHA256,
			hashFunc: sha256.New,
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			tpm, err := simulator.Get()
			if err != nil {
				t.Fatalf("couldn't get TPM simulator: %v", err)
			}
			defer tpm.Close()

			// Create primary key.
			parent, _, _, _, _, _, err := tpm2.CreatePrimaryEx(tpm, tpm2.HandleOwner,
				tpm2.PCRSelection{}, "", "", parentPub)
			if err != nil {
				t.Fatalf("couldn't create primary key: %v", err)
			}
			defer func() {
				if err := tpm2.FlushContext(tpm, parent); err != nil {
					t.Errorf("couldn't flush primary key: %v", err)
				}
			}()

			// Create and load key signing key.
			private, public, _, _, _, err := tpm2.CreateKey(tpm, parent,
				tpm2.PCRSelection{}, "", "", tc.public)
			if err != nil {
				t.Fatalf("couldn't create attestation key: %v", err)
			}

			handle, _, err := tpm2.Load(tpm, parent, "", public, private)
			if err != nil {
				t.Fatalf("couldn't load attestation key: %v", err)
			}
			defer func() {
				if err := tpm2.FlushContext(tpm, handle); err != nil {
					t.Errorf("couldn't flush attestation key: %v", err)
				}
			}()

			// Get private signing key.
			key, err := pgtpm.PrivateKeyFromActiveHandle(tpm, handle)
			if err != nil {
				t.Fatalf("couldn't get private key: %v", err)
			}

			// Calculate and sign digest.

			hash := tc.hashFunc()
			hash.Write([]byte("some random message"))
			digest := hash.Sum(nil)

			sig, err := key.Sign(rand.Reader, digest, tc.hash)
			if err != nil {
				t.Fatalf("couldn't sign: %v", err)
			}

			// Verify signature.
			err = rsa.VerifyPKCS1v15(key.Public().(*rsa.PublicKey), tc.hash, digest, sig)
			if err != nil {
				t.Fatalf("couldn't verify signature: %v", err)
			}
		})
	}
}

func TestPrivateKeyFromActiveHandleECCSign(t *testing.T) {
	var parentPub = tpm2.Public{
		Type:       tpm2.AlgRSA,
		NameAlg:    tpm2.AlgSHA256,
		Attributes: tpm2.FlagStorageDefault,
		RSAParameters: &tpm2.RSAParams{
			Symmetric: &tpm2.SymScheme{
				Alg:     tpm2.AlgAES,
				KeyBits: 128,
				Mode:    tpm2.AlgCFB,
			},
			KeyBits: 2048,
		},
	}

	var testcases = []struct {
		name     string
		public   tpm2.Public
		hash     crypto.Hash
		hashFunc func() hash.Hash
	}{
		{
			name: "ECC/ECDSA/SHA256/SHA256",
			public: tpm2.Public{
				Type:       tpm2.AlgECC,
				NameAlg:    tpm2.AlgSHA256,
				Attributes: tpm2.FlagSignerDefault & ^tpm2.FlagRestricted,
				ECCParameters: &tpm2.ECCParams{
					Sign: &tpm2.SigScheme{
						Alg:  tpm2.AlgECDSA,
						Hash: tpm2.AlgSHA256,
					},
					CurveID: tpm2.CurveNISTP256,
				},
			},
			hash:     crypto.SHA256,
			hashFunc: sha256.New,
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			tpm, err := simulator.Get()
			if err != nil {
				t.Fatalf("couldn't get TPM simulator: %v", err)
			}
			defer tpm.Close()

			// Create primary key.
			parent, _, _, _, _, _, err := tpm2.CreatePrimaryEx(tpm, tpm2.HandleOwner,
				tpm2.PCRSelection{}, "", "", parentPub)
			if err != nil {
				t.Fatalf("couldn't create primary key: %v", err)
			}
			defer func() {
				if err := tpm2.FlushContext(tpm, parent); err != nil {
					t.Errorf("couldn't flush primary key: %v", err)
				}
			}()

			// Create and load key signing key.
			private, public, _, _, _, err := tpm2.CreateKey(tpm, parent,
				tpm2.PCRSelection{}, "", "", tc.public)
			if err != nil {
				t.Fatalf("couldn't create attestation key: %v", err)
			}

			handle, _, err := tpm2.Load(tpm, parent, "", public, private)
			if err != nil {
				t.Fatalf("couldn't load attestation key: %v", err)
			}
			defer func() {
				if err := tpm2.FlushContext(tpm, handle); err != nil {
					t.Errorf("couldn't flush attestation key: %v", err)
				}
			}()

			// Get private signing key.
			key, err := pgtpm.PrivateKeyFromActiveHandle(tpm, handle)
			if err != nil {
				t.Fatalf("couldn't get private key: %v", err)
			}

			// Calculate and sign digest.

			hash := tc.hashFunc()
			hash.Write([]byte("some random message"))
			digest := hash.Sum(nil)

			sig, err := key.Sign(rand.Reader, digest, tc.hash)
			if err != nil {
				t.Fatalf("couldn't sign: %v", err)
			}

			// Unmarshal and verify signature.
			var esig = struct {
				R *big.Int
				S *big.Int
			}{}

			if _, err := asn1.Unmarshal(sig, &esig); err != nil {
				t.Fatalf("couldn't unmarshal signature: %v", err)
			}

			if ok := ecdsa.Verify(key.Public().(*ecdsa.PublicKey), digest, esig.R, esig.S); !ok {
				t.Fatalf("failed to verify signature")
			}
		})
	}
}
