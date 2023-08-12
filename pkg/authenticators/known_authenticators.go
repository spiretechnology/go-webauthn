package authenticators

import (
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
)

var (
	//go:embed known_authenticators.json
	knownAuthenticatorsJSON []byte

	knownAuthenticators = loadKnownAuthenticators()
)

type knownAuthenticatorJSON struct {
	AAGUID       string `json:"aaguid"`
	Manufacturer string `json:"manufacturer"`
	Model        string `json:"model"`
	Name         string `json:"name"`
}

func loadKnownAuthenticators() map[AAGUID]Authenticator {
	// Parse the embedded json file
	var authenticators []knownAuthenticatorJSON
	if err := json.Unmarshal(knownAuthenticatorsJSON, &authenticators); err != nil {
		panic(err)
	}

	// Convert it into a map with the AAGUID as the key
	knownAuthenticators := map[AAGUID]Authenticator{}
	for _, a := range authenticators {
		aaguid, err := parseAAGUID(a.AAGUID)
		if err != nil {
			panic(err)
		}
		knownAuthenticators[aaguid] = Authenticator{
			AAGUID:       aaguid,
			Manufacturer: a.Manufacturer,
			Model:        a.Model,
			Name:         a.Name,
		}
	}
	return knownAuthenticators
}

func parseAAGUID(str string) (AAGUID, error) {
	var aaguid AAGUID
	str = strings.ReplaceAll(str, "-", "")
	if len(str) != 32 {
		return aaguid, errors.New("invalid AAGUID")
	}
	aaguidSlice, err := hex.DecodeString(str)
	if err != nil {
		return aaguid, err
	}
	copy(aaguid[:], aaguidSlice)
	return aaguid, nil
}
