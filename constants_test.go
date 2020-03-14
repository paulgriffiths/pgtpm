package pgtpm_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/paulgriffiths/pgtpm"
)

func TestAlgorithmString(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name  string
		value pgtpm.Algorithm
		want  string
	}{
		{
			name:  "Valid",
			value: pgtpm.TPM2_ALG_RSA,
			want:  "TPM2_ALG_RSA",
		},
		{
			name:  "Invalid",
			value: 9999,
			want:  "UNKNOWN ALGORITHM VALUE",
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got := tc.value.String(); got != tc.want {
				t.Errorf("got %s, want %s", got, tc.want)
			}
		})
	}
}

func TestAlgorithmMarshalJSON(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name  string
		value pgtpm.Algorithm
		want  []byte
		err   error
	}{
		{
			name:  "Valid",
			value: pgtpm.TPM2_ALG_RSA,
			want:  []byte(`"TPM2_ALG_RSA"`),
		},
		{
			name:  "Invalid",
			value: 9999,
			err:   errors.New("invalid value"),
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := json.Marshal(tc.value)
			if (err == nil) != (tc.err == nil) {
				t.Fatalf("got error %v, want %v", err, tc.err)
			}

			if !bytes.Equal(got, tc.want) {
				t.Errorf("got %s, want %s", string(got), string(tc.want))
			}
		})
	}
}

func TestAlgorithmUnmarshalJSON(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name  string
		value []byte
		want  pgtpm.Algorithm
		err   error
	}{
		{
			name:  "Valid",
			value: []byte(`"TPM2_ALG_ECC"`),
			want:  pgtpm.TPM2_ALG_ECC,
		},
		{
			name:  "BadValue",
			value: []byte(`"NOT_A_VALID_VALUE"`),
			err:   errors.New("invalid value"),
		},
		{
			name:  "BadType",
			value: []byte(`false`),
			err:   errors.New("invalid type"),
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var got pgtpm.Algorithm

			err := json.Unmarshal(tc.value, &got)
			if (err == nil) != (tc.err == nil) {
				t.Fatalf("got error %v, want %v", err, tc.err)
			}

			if got != tc.want {
				t.Errorf("got %d, want %d", got, tc.want)
			}
		})
	}
}

func TestAlgorithmAttributeString(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name  string
		value pgtpm.AlgorithmAttribute
		want  string
	}{
		{
			name:  "Valid",
			value: pgtpm.TPMA_ALGORITHM_ASYMMETRIC,
			want:  "TPMA_ALGORITHM_ASYMMETRIC",
		},
		{
			name:  "Invalid",
			value: 99999999,
			want:  "UNKNOWN ALGORITHM ATTRIBUTE VALUE",
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got := tc.value.String(); got != tc.want {
				t.Errorf("got %s, want %s", got, tc.want)
			}
		})
	}
}

func TestAlgorithmAttributeMarshalJSON(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name  string
		value pgtpm.AlgorithmAttribute
		want  []byte
		err   error
	}{
		{
			name:  "Valid",
			value: pgtpm.TPMA_ALGORITHM_ASYMMETRIC,
			want:  []byte(`"TPMA_ALGORITHM_ASYMMETRIC"`),
		},
		{
			name:  "Invalid",
			value: 99999999,
			err:   errors.New("invalid value"),
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := json.Marshal(tc.value)
			if (err == nil) != (tc.err == nil) {
				t.Fatalf("got error %v, want %v", err, tc.err)
			}

			if !bytes.Equal(got, tc.want) {
				t.Errorf("got %s, want %s", string(got), string(tc.want))
			}
		})
	}
}

func TestAlgorithmAttributeUnmarshalJSON(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name  string
		value []byte
		want  pgtpm.AlgorithmAttribute
		err   error
	}{
		{
			name:  "Valid",
			value: []byte(`"TPMA_ALGORITHM_ASYMMETRIC"`),
			want:  pgtpm.TPMA_ALGORITHM_ASYMMETRIC,
		},
		{
			name:  "BadValue",
			value: []byte(`"NOT_A_VALID_VALUE"`),
			err:   errors.New("invalid value"),
		},
		{
			name:  "BadType",
			value: []byte(`false`),
			err:   errors.New("invalid type"),
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var got pgtpm.AlgorithmAttribute

			err := json.Unmarshal(tc.value, &got)
			if (err == nil) != (tc.err == nil) {
				t.Fatalf("got error %v, want %v", err, tc.err)
			}

			if got != tc.want {
				t.Errorf("got %d, want %d", got, tc.want)
			}
		})
	}
}

func TestCapabilityString(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name  string
		value pgtpm.Capability
		want  string
	}{
		{
			name:  "Valid",
			value: pgtpm.TPM2_CAP_HANDLES,
			want:  "TPM2_CAP_HANDLES",
		},
		{
			name:  "Invalid",
			value: 99999999,
			want:  "UNKNOWN CAPABILITY VALUE",
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got := tc.value.String(); got != tc.want {
				t.Errorf("got %s, want %s", got, tc.want)
			}
		})
	}
}

func TestCapabilityMarshalJSON(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name  string
		value pgtpm.Capability
		want  []byte
		err   error
	}{
		{
			name:  "Valid",
			value: pgtpm.TPM2_CAP_HANDLES,
			want:  []byte(`"TPM2_CAP_HANDLES"`),
		},
		{
			name:  "Invalid",
			value: 99999999,
			err:   errors.New("invalid value"),
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := json.Marshal(tc.value)
			if (err == nil) != (tc.err == nil) {
				t.Fatalf("got error %v, want %v", err, tc.err)
			}

			if !bytes.Equal(got, tc.want) {
				t.Errorf("got %s, want %s", string(got), string(tc.want))
			}
		})
	}
}

func TestCapabilityUnmarshalJSON(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name  string
		value []byte
		want  pgtpm.Capability
		err   error
	}{
		{
			name:  "Valid",
			value: []byte(`"TPM2_CAP_ALGS"`),
			want:  pgtpm.TPM2_CAP_ALGS,
		},
		{
			name:  "BadValue",
			value: []byte(`"NOT_A_VALID_VALUE"`),
			err:   errors.New("invalid value"),
		},
		{
			name:  "BadType",
			value: []byte(`false`),
			err:   errors.New("invalid type"),
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var got pgtpm.Capability

			err := json.Unmarshal(tc.value, &got)
			if (err == nil) != (tc.err == nil) {
				t.Fatalf("got error %v, want %v", err, tc.err)
			}

			if got != tc.want {
				t.Errorf("got %d, want %d", got, tc.want)
			}
		})
	}
}

func TestCommandString(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name  string
		value pgtpm.Command
		want  string
	}{
		{
			name:  "Valid",
			value: pgtpm.TPM2_CC_GetCapability,
			want:  "TPM2_CC_GetCapability",
		},
		{
			name:  "Invalid",
			value: 99999999,
			want:  "UNKNOWN COMMAND VALUE",
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got := tc.value.String(); got != tc.want {
				t.Errorf("got %s, want %s", got, tc.want)
			}
		})
	}
}

func TestCommandMarshalJSON(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name  string
		value pgtpm.Command
		want  []byte
		err   error
	}{
		{
			name:  "Valid",
			value: pgtpm.TPM2_CC_MakeCredential,
			want:  []byte(`"TPM2_CC_MakeCredential"`),
		},
		{
			name:  "Invalid",
			value: 99999999,
			err:   errors.New("invalid value"),
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := json.Marshal(tc.value)
			if (err == nil) != (tc.err == nil) {
				t.Fatalf("got error %v, want %v", err, tc.err)
			}

			if !bytes.Equal(got, tc.want) {
				t.Errorf("got %s, want %s", string(got), string(tc.want))
			}
		})
	}
}

func TestCommandUnmarshalJSON(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name  string
		value []byte
		want  pgtpm.Command
		err   error
	}{
		{
			name:  "Valid",
			value: []byte(`"TPM2_CC_NV_ReadPublic"`),
			want:  pgtpm.TPM2_CC_NV_ReadPublic,
		},
		{
			name:  "BadValue",
			value: []byte(`"NOT_A_VALID_VALUE"`),
			err:   errors.New("invalid value"),
		},
		{
			name:  "BadType",
			value: []byte(`false`),
			err:   errors.New("invalid type"),
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var got pgtpm.Command

			err := json.Unmarshal(tc.value, &got)
			if (err == nil) != (tc.err == nil) {
				t.Fatalf("got error %v, want %v", err, tc.err)
			}

			if got != tc.want {
				t.Errorf("got %d, want %d", got, tc.want)
			}
		})
	}
}

func TestEllipticCurveString(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name  string
		value pgtpm.EllipticCurve
		want  string
	}{
		{
			name:  "Valid",
			value: pgtpm.TPM2_ECC_SM2_P256,
			want:  "TPM2_ECC_SM2_P256",
		},
		{
			name:  "Invalid",
			value: 9999,
			want:  "UNKNOWN ELLIPTIC CURVE VALUE",
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got := tc.value.String(); got != tc.want {
				t.Errorf("got %s, want %s", got, tc.want)
			}
		})
	}
}

func TestEllipticCurveMarshalJSON(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name  string
		value pgtpm.EllipticCurve
		want  []byte
		err   error
	}{
		{
			name:  "Valid",
			value: pgtpm.TPM2_ECC_BN_P256,
			want:  []byte(`"TPM2_ECC_BN_P256"`),
		},
		{
			name:  "Invalid",
			value: 9999,
			err:   errors.New("invalid value"),
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := json.Marshal(tc.value)
			if (err == nil) != (tc.err == nil) {
				t.Fatalf("got error %v, want %v", err, tc.err)
			}

			if !bytes.Equal(got, tc.want) {
				t.Errorf("got %s, want %s", string(got), string(tc.want))
			}
		})
	}
}

func TestEllipticCurveUnmarshalJSON(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name  string
		value []byte
		want  pgtpm.EllipticCurve
		err   error
	}{
		{
			name:  "Valid",
			value: []byte(`"TPM2_ECC_NIST_P256"`),
			want:  pgtpm.TPM2_ECC_NIST_P256,
		},
		{
			name:  "BadValue",
			value: []byte(`"NOT_A_VALID_VALUE"`),
			err:   errors.New("invalid value"),
		},
		{
			name:  "BadType",
			value: []byte(`false`),
			err:   errors.New("invalid type"),
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var got pgtpm.EllipticCurve

			err := json.Unmarshal(tc.value, &got)
			if (err == nil) != (tc.err == nil) {
				t.Fatalf("got error %v, want %v", err, tc.err)
			}

			if got != tc.want {
				t.Errorf("got %d, want %d", got, tc.want)
			}
		})
	}
}

func TestHandleHandleType(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		value pgtpm.Handle
		want  pgtpm.HandleType
	}{
		{
			value: 0x00000001,
			want:  pgtpm.TPM2_HT_PCR,
		},
		{
			value: 0x01000001,
			want:  pgtpm.TPM2_HT_NV_INDEX,
		},
		{
			value: 0x40000001,
			want:  pgtpm.TPM2_HT_PERMANENT,
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(fmt.Sprintf("0x%08x", tc.value), func(t *testing.T) {
			t.Parallel()

			if got := tc.value.HandleType(); got != tc.want {
				t.Errorf("got %s, want %s", got.String(), tc.want.String())
			}
		})
	}
}

func TestHandleTypeFirst(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		value pgtpm.HandleType
		want  pgtpm.Handle
	}{
		{
			value: pgtpm.TPM2_HT_PCR,
			want:  0x00000000,
		},
		{
			value: pgtpm.TPM2_HT_NV_INDEX,
			want:  0x01000000,
		},
		{
			value: pgtpm.TPM2_HT_PERMANENT,
			want:  0x40000000,
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.value.String(), func(t *testing.T) {
			t.Parallel()

			if got := tc.value.First(); got != tc.want {
				t.Errorf("got 0x%08x, want 0x%08x", got, tc.want)
			}
		})
	}
}

func TestHandleTypeString(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name  string
		value pgtpm.HandleType
		want  string
	}{
		{
			name:  "Valid",
			value: pgtpm.TPM2_HT_PERSISTENT,
			want:  "TPM2_HT_PERSISTENT",
		},
		{
			name:  "Invalid",
			value: 99999999,
			want:  "UNKNOWN HANDLE TYPE VALUE",
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got := tc.value.String(); got != tc.want {
				t.Errorf("got %s, want %s", got, tc.want)
			}
		})
	}
}

func TestHandleTypeMarshalJSON(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name  string
		value pgtpm.HandleType
		want  []byte
		err   error
	}{
		{
			name:  "Valid",
			value: pgtpm.TPM2_HT_PCR,
			want:  []byte(`"TPM2_HT_PCR"`),
		},
		{
			name:  "Invalid",
			value: 99999999,
			err:   errors.New("invalid value"),
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := json.Marshal(tc.value)
			if (err == nil) != (tc.err == nil) {
				t.Fatalf("got error %v, want %v", err, tc.err)
			}

			if !bytes.Equal(got, tc.want) {
				t.Errorf("got %s, want %s", string(got), string(tc.want))
			}
		})
	}
}

func TestHandleTypeUnmarshalJSON(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name  string
		value []byte
		want  pgtpm.HandleType
		err   error
	}{
		{
			name:  "Valid",
			value: []byte(`"TPM2_HT_NV_INDEX"`),
			want:  pgtpm.TPM2_HT_NV_INDEX,
		},
		{
			name:  "BadValue",
			value: []byte(`"NOT_A_VALID_VALUE"`),
			err:   errors.New("invalid value"),
		},
		{
			name:  "BadType",
			value: []byte(`false`),
			err:   errors.New("invalid type"),
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var got pgtpm.HandleType

			err := json.Unmarshal(tc.value, &got)
			if (err == nil) != (tc.err == nil) {
				t.Fatalf("got error %v, want %v", err, tc.err)
			}

			if got != tc.want {
				t.Errorf("got %d, want %d", got, tc.want)
			}
		})
	}
}

func TestObjectAttributeString(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name  string
		value pgtpm.ObjectAttribute
		want  string
	}{
		{
			name:  "Valid",
			value: pgtpm.TPMA_OBJECT_DECRYPT,
			want:  "TPMA_OBJECT_DECRYPT",
		},
		{
			name:  "Invalid",
			value: 99999999,
			want:  "UNKNOWN OBJECT ATTRIBUTE VALUE",
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got := tc.value.String(); got != tc.want {
				t.Errorf("got %s, want %s", got, tc.want)
			}
		})
	}
}

func TestObjectAttributeMarshalJSON(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name  string
		value pgtpm.ObjectAttribute
		want  []byte
		err   error
	}{
		{
			name:  "Valid",
			value: pgtpm.TPMA_OBJECT_DECRYPT,
			want:  []byte(`"TPMA_OBJECT_DECRYPT"`),
		},
		{
			name:  "Invalid",
			value: 99999999,
			err:   errors.New("invalid value"),
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := json.Marshal(tc.value)
			if (err == nil) != (tc.err == nil) {
				t.Fatalf("got error %v, want %v", err, tc.err)
			}

			if !bytes.Equal(got, tc.want) {
				t.Errorf("got %s, want %s", string(got), string(tc.want))
			}
		})
	}
}

func TestObjectAttributeUnmarshalJSON(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name  string
		value []byte
		want  pgtpm.ObjectAttribute
		err   error
	}{
		{
			name:  "Valid",
			value: []byte(`"TPMA_OBJECT_SIGN_ENCRYPT"`),
			want:  pgtpm.TPMA_OBJECT_SIGN_ENCRYPT,
		},
		{
			name:  "BadValue",
			value: []byte(`"NOT_A_VALID_VALUE"`),
			err:   errors.New("invalid value"),
		},
		{
			name:  "BadType",
			value: []byte(`false`),
			err:   errors.New("invalid type"),
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var got pgtpm.ObjectAttribute

			err := json.Unmarshal(tc.value, &got)
			if (err == nil) != (tc.err == nil) {
				t.Fatalf("got error %v, want %v", err, tc.err)
			}

			if got != tc.want {
				t.Errorf("got %d, want %d", got, tc.want)
			}
		})
	}
}
