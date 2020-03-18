package pgtpm_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"hash"
	"log"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2"

	"github.com/paulgriffiths/pgtpm"
	"github.com/paulgriffiths/pki/pkifile"
)

type testHandler struct{}

func (h testHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusTeapot)
	return
}

func TestPrivateKeyFromActiveHandleTLSClient(t *testing.T) {
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

	childPub := tpm2.Public{
		Type:       tpm2.AlgRSA,
		NameAlg:    tpm2.AlgSHA256,
		Attributes: tpm2.FlagSignerDefault & ^tpm2.FlagRestricted,
		RSAParameters: &tpm2.RSAParams{
			KeyBits: 2048,
		},
	}

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
		tpm2.PCRSelection{}, "", "", childPub)
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

	// Get CA certificate and key.
	caCert, err := pkifile.CertFromPEMFile("testdata/ca_cert.pem")
	if err != nil {
		t.Fatalf("couldn't get CA certificate from file: %v", err)
	}

	caKey, err := pkifile.PrivateKeyFromPEMFile("testdata/ca_key.pem")
	if err != nil {
		t.Fatalf("couldn't get CA private key from file: %v", err)
	}

	// Create client certificate.
	now := time.Now()

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1984),
		NotBefore:             now,
		NotAfter:              now.Add(time.Hour * 24),
		Subject:               pkix.Name{CommonName: "TPM User"},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	clientCertDER, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, key.Public(), caKey)
	if err != nil {
		t.Fatalf("couldn't create certificate: %v", err)
	}

	clientCert, err := x509.ParseCertificate(clientCertDER)
	if err != nil {
		t.Fatalf("couldn't parse certificate: %v", err)
	}

	// Create and configure test server.
	s := httptest.NewUnstartedServer(testHandler{})
	s.TLS = &tls.Config{
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:  x509.NewCertPool(),
	}
	s.Config.ErrorLog = log.New(os.Stderr, "test: ", 0)
	s.TLS.ClientCAs.AddCert(caCert)
	s.StartTLS()
	defer s.Close()

	// Make request to test server.
	c := s.Client()
	trans := c.Transport.(*http.Transport)
	trans.TLSClientConfig.Certificates = []tls.Certificate{
		tls.Certificate{
			Certificate: [][]byte{clientCert.Raw},
			PrivateKey:  key,
			Leaf:        clientCert,
		},
	}

	req, err := http.NewRequest(http.MethodGet, s.URL+"/endpoint", nil)
	if err != nil {
		t.Fatalf("couldn't make HTTP request: %v", err)
	}

	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("couldn't executed HTTP request: %v", err)
	}

	// Check request was successful.
	if resp.StatusCode != http.StatusTeapot {
		t.Fatalf("got status %d, want %d", resp.StatusCode, http.StatusTeapot)
	}
}

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
