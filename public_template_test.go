package pgtpm_test

import (
	"encoding/json"
	"io/ioutil"
	"reflect"
	"testing"

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
