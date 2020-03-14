package pgtpm

type PublicTemplate struct {
	Type       Algorithm         `json:"type"`
	NameAlg    Algorithm         `json:"name_alg"`
	Attributes []ObjectAttribute `json:"attributes,omitempty"`
}
