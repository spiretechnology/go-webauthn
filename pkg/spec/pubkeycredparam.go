package spec

// PubKeyCredParam defines a supported type of public key and its signature algorithm.
type PubKeyCredParam struct {
	Type string `json:"type"`
	Alg  int    `json:"alg"`
}
