package pgtpm_test

import (
	"bytes"
	"testing"

	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2"

	"github.com/paulgriffiths/pgtpm"
)

func TestMakeCredential(t *testing.T) {
	var testcases = []struct {
		name  string
		cred  []byte
		ekPub tpm2.Public
		akPub tpm2.Public
	}{
		{
			name: "RSA/AES128",
			cred: []byte(`Hello, world!`),
			ekPub: tpm2.Public{
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
			},
			akPub: tpm2.Public{
				Type:       tpm2.AlgRSA,
				NameAlg:    tpm2.AlgSHA256,
				Attributes: tpm2.FlagSignerDefault,
				RSAParameters: &tpm2.RSAParams{
					Sign: &tpm2.SigScheme{
						Alg:  tpm2.AlgRSAPSS,
						Hash: tpm2.AlgSHA256,
					},
					KeyBits: 2048,
				},
			},
		},
		{
			name: "RSA/AES256",
			cred: []byte(`"Commonplace, Watson."`),
			ekPub: tpm2.Public{
				Type:       tpm2.AlgRSA,
				NameAlg:    tpm2.AlgSHA256,
				Attributes: tpm2.FlagStorageDefault,
				RSAParameters: &tpm2.RSAParams{
					Symmetric: &tpm2.SymScheme{
						Alg:     tpm2.AlgAES,
						KeyBits: 256,
						Mode:    tpm2.AlgCFB,
					},
					KeyBits: 2048,
				},
			},
			akPub: tpm2.Public{
				Type:       tpm2.AlgRSA,
				NameAlg:    tpm2.AlgSHA256,
				Attributes: tpm2.FlagSignerDefault,
				RSAParameters: &tpm2.RSAParams{
					Sign: &tpm2.SigScheme{
						Alg:  tpm2.AlgRSAPSS,
						Hash: tpm2.AlgSHA256,
					},
					KeyBits: 2048,
				},
			},
		},
		{
			name: "ECC/AES128",
			cred: []byte(`worm-filled`),
			ekPub: tpm2.Public{
				Type:       tpm2.AlgECC,
				NameAlg:    tpm2.AlgSHA256,
				Attributes: tpm2.FlagStorageDefault,
				ECCParameters: &tpm2.ECCParams{
					Symmetric: &tpm2.SymScheme{
						Alg:     tpm2.AlgAES,
						KeyBits: 128,
						Mode:    tpm2.AlgCFB,
					},
					CurveID: tpm2.CurveNISTP256,
				},
			},
			akPub: tpm2.Public{
				Type:       tpm2.AlgRSA,
				NameAlg:    tpm2.AlgSHA256,
				Attributes: tpm2.FlagSignerDefault,
				RSAParameters: &tpm2.RSAParams{
					Sign: &tpm2.SigScheme{
						Alg:  tpm2.AlgRSAPSS,
						Hash: tpm2.AlgSHA256,
					},
					KeyBits: 2048,
				},
			},
		},
		{
			name: "ECC/AES256",
			cred: []byte(`trilby hat`),
			ekPub: tpm2.Public{
				Type:       tpm2.AlgECC,
				NameAlg:    tpm2.AlgSHA256,
				Attributes: tpm2.FlagStorageDefault,
				ECCParameters: &tpm2.ECCParams{
					Symmetric: &tpm2.SymScheme{
						Alg:     tpm2.AlgAES,
						KeyBits: 256,
						Mode:    tpm2.AlgCFB,
					},
					CurveID: tpm2.CurveNISTP256,
				},
			},
			akPub: tpm2.Public{
				Type:       tpm2.AlgRSA,
				NameAlg:    tpm2.AlgSHA256,
				Attributes: tpm2.FlagSignerDefault,
				RSAParameters: &tpm2.RSAParams{
					Sign: &tpm2.SigScheme{
						Alg:  tpm2.AlgRSAPSS,
						Hash: tpm2.AlgSHA256,
					},
					KeyBits: 2048,
				},
			},
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

			// Create endorsement key.
			ek, ekPub, _, _, _, _, err := tpm2.CreatePrimaryEx(tpm, tpm2.HandleOwner,
				tpm2.PCRSelection{}, "", "", tc.ekPub)
			if err != nil {
				t.Fatalf("couldn't create primary key: %v", err)
			}
			defer func() {
				if err := tpm2.FlushContext(tpm, ek); err != nil {
					t.Errorf("couldn't flush primary key: %v", err)
				}
			}()

			// Create and load key attestation key.
			akPriv, akPub, _, _, _, err := tpm2.CreateKey(tpm, ek,
				tpm2.PCRSelection{}, "", "", tc.akPub)
			if err != nil {
				t.Fatalf("couldn't create attestation key: %v", err)
			}

			ak, _, err := tpm2.Load(tpm, ek, "", akPub, akPriv)
			if err != nil {
				t.Fatalf("couldn't load attestation key: %v", err)
			}
			defer func() {
				if err := tpm2.FlushContext(tpm, ak); err != nil {
					t.Errorf("couldn't flush attestation key: %v", err)
				}
			}()

			// Make credential.
			cred, secret, err := pgtpm.MakeCredential(tc.cred, ekPub, akPub)
			if err != nil {
				t.Fatalf("couldn't make credential: %v", err)
			}

			// Activate credential via TPM.
			got, err := tpm2.ActivateCredential(tpm, ak, ek, "", "", cred, secret)
			if err != nil {
				t.Fatalf("couldn't activate credential: %v", err)
			}

			// Check activated credential is as expected.
			if !bytes.Equal(got, tc.cred) {
				t.Fatalf("got %q, want %q", string(got), string(tc.cred))
			}
		})
	}
}
