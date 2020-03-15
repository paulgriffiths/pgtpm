package pgtpm_test

import (
	"encoding/json"
	"io/ioutil"
	"math/big"
	"reflect"
	"testing"

	"github.com/google/go-tpm/tpm2"

	"github.com/paulgriffiths/pgtpm"
)

func TestPublicTemplateUnmarshalJSON(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		filename string
		want     pgtpm.PublicTemplate
	}{
		{
			filename: "testdata/public_template_1.json",
			want: pgtpm.PublicTemplate{
				Type:    pgtpm.TPM2_ALG_RSA,
				NameAlg: pgtpm.TPM2_ALG_SHA256,
				Attributes: []pgtpm.ObjectAttribute{
					pgtpm.TPMA_OBJECT_RESTRICTED,
					pgtpm.TPMA_OBJECT_USERWITHAUTH,
					pgtpm.TPMA_OBJECT_SIGN_ENCRYPT,
					pgtpm.TPMA_OBJECT_FIXEDTPM,
					pgtpm.TPMA_OBJECT_FIXEDPARENT,
					pgtpm.TPMA_OBJECT_SENSITIVEDATAORIGIN,
				},
				RSAParameters: &pgtpm.RSAParams{
					Symmetric: &pgtpm.SymScheme{
						Alg:     pgtpm.TPM2_ALG_AES,
						KeyBits: 128,
						Mode:    pgtpm.TPM2_ALG_CFB,
					},
					Sign: &pgtpm.SigScheme{
						Alg:  pgtpm.TPM2_ALG_RSAPSS,
						Hash: pgtpm.TPM2_ALG_SHA256,
					},
					KeyBits:  2048,
					Exponent: 65537,
					Modulus:  big.NewInt(102387),
				},
				ECCParameters: &pgtpm.ECCParams{
					Symmetric: &pgtpm.SymScheme{
						Alg:     pgtpm.TPM2_ALG_AES,
						KeyBits: 256,
						Mode:    pgtpm.TPM2_ALG_OFB,
					},
					Sign: &pgtpm.SigScheme{
						Alg:  pgtpm.TPM2_ALG_ECDSA,
						Hash: pgtpm.TPM2_ALG_SHA256,
					},
					CurveID: pgtpm.TPM2_ECC_NIST_P256,
					KDF: &pgtpm.KDFScheme{
						Alg:  pgtpm.TPM2_ALG_KDF1_SP800_108,
						Hash: pgtpm.TPM2_ALG_SHA384,
					},
					Point: &pgtpm.ECPoint{
						X: big.NewInt(42),
						Y: big.NewInt(99),
					},
				},
				SymCipherParameters: &pgtpm.SymCipherParams{
					Symmetric: &pgtpm.SymScheme{
						Alg:     pgtpm.TPM2_ALG_TDES,
						KeyBits: 64,
						Mode:    pgtpm.TPM2_ALG_CBC,
					},
				},
				KeyedHashParameters: &pgtpm.KeyedHashParams{
					Alg:  pgtpm.TPM2_ALG_HMAC,
					Hash: pgtpm.TPM2_ALG_SHA512,
					KDF:  pgtpm.TPM2_ALG_KDF1_SP800_56A,
				},
			},
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.filename, func(t *testing.T) {
			t.Parallel()

			b, err := ioutil.ReadFile(tc.filename)
			if err != nil {
				t.Fatalf("couldn't read file: %v", err)
			}

			var got pgtpm.PublicTemplate
			if err := json.Unmarshal(b, &got); err != nil {
				t.Fatalf("couldn't unmarshal JSON: %v", err)
			}

			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestPublicTemplateToPublic(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		tmpl string
		pub  string
	}{
		{tmpl: "testdata/rsa_key.json", pub: "testdata/rsa_key.public"},
		{tmpl: "testdata/ecc_key.json", pub: "testdata/ecc_key.public"},
		{tmpl: "testdata/rsa_storage.json", pub: "testdata/rsa_storage.public"},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.tmpl, func(t *testing.T) {
			t.Parallel()

			data, err := ioutil.ReadFile(tc.tmpl)
			if err != nil {
				t.Fatalf("couldn't read template from file: %v", err)
			}

			var tmpl pgtpm.PublicTemplate
			if err := json.Unmarshal(data, &tmpl); err != nil {
				t.Fatalf("couldn't unmarshal template: %v", err)
			}

			got := tmpl.ToPublic()

			data, err = ioutil.ReadFile(tc.pub)
			if err != nil {
				t.Fatalf("couldn't read public area from file: %v", err)
			}

			want, err := tpm2.DecodePublic(data)
			if err != nil {
				t.Fatalf("couldn't decode public area: %v", err)
			}

			if !reflect.DeepEqual(got, want) {
				t.Errorf("got %v, want %v", got, want)
				t.Errorf("got %v, want %v", got.RSAParameters, want.RSAParameters)
				t.Errorf("got %v, want %v", got.RSAParameters.Symmetric, want.RSAParameters.Symmetric)
			}
		})
	}
}
