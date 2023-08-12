package spec

import (
	"crypto"
	"crypto/x509"
	"encoding/asn1"
	"encoding/json"
	"log"

	"github.com/fxamacker/cbor/v2"
	"github.com/spiretechnology/go-webauthn/internal/errutil"
	"github.com/spiretechnology/go-webauthn/pkg/errs"
	"github.com/spiretechnology/go-webauthn/pkg/pubkey"
	"golang.org/x/exp/slices"
)

// AuthenticatorAttestationResponse is a registration response.
type AuthenticatorAttestationResponse struct {
	ClientDataJSON        []byte
	AttestationObjectCBOR []byte

	clientData        *ClientData
	attestationObject *AttestationObject
}

func (a *AuthenticatorAttestationResponse) ClientData() (*ClientData, error) {
	if a.clientData == nil {
		var clientData ClientData
		if err := json.Unmarshal(a.ClientDataJSON, &clientData); err != nil {
			return nil, errutil.Wrapf(err, "decoding json")
		}
		a.clientData = &clientData
	}
	return a.clientData, nil
}

func (a *AuthenticatorAttestationResponse) AttestationObject() (*AttestationObject, error) {
	if a.attestationObject == nil {
		var attestationObject AttestationObject
		if err := cbor.Unmarshal(a.AttestationObjectCBOR, &attestationObject); err != nil {
			return nil, errutil.Wrapf(err, "decoding cbor")
		}
		a.attestationObject = &attestationObject
	}
	return a.attestationObject, nil
}

// const id-fido-gen-ce-aaguid
var CertExtID_FidoGenCEAAGUID = []int{1, 3, 6, 1, 4, 1, 45724, 1, 1, 4}

// Verify checks a signed WebAuthn response against the public key of the device.
func (a *AuthenticatorAttestationResponse) Verify() error {
	// Get the attestation object
	attestationObj, err := a.AttestationObject()
	if err != nil {
		return errutil.Wrapf(err, "getting attestation object")
	}

	switch attestationObj.Fmt {
	case "none":
		// If the format is "none", no more verification is needed
		return nil
	case "packed":
		return a.verifyPackedAttestation(attestationObj)
	default:
		return errutil.Newf("unsupported attestation format: %s", attestationObj.Fmt)
	}
}

func (a *AuthenticatorAttestationResponse) verifyPackedAttestation(attestationObj *AttestationObject) error {
	// Get the authenticator data from the attestation object
	authData, err := attestationObj.AuthenticatorData()
	if err != nil {
		return errutil.Wrapf(err, "getting authenticator data")
	}

	// Get the algorithm from the attestation object
	alg, ok := attestationObj.AttStmt["alg"].(int64)
	if !ok {
		return errutil.New("algorithm not found")
	}

	// Get the expected signature
	signature, ok := attestationObj.AttStmt["sig"].([]byte)
	if !ok {
		return errutil.New("signature not found")
	}

	// If x5c is present, this is a full attestation
	if x5c, ok := attestationObj.AttStmt["x5c"]; ok {
		// Get the certificate chain, which is a list of certificates
		certChain, ok := x5c.([]any)
		if !ok || len(certChain) == 0 {
			return errutil.New("certificate chain not found")
		}

		// Get the certificate
		attestnCert, ok := certChain[0].([]uint8)
		if !ok {
			return errutil.New("certificate not found")
		}

		// Decode the certificate from X.509
		cert, err := x509.ParseCertificate(attestnCert)
		if err != nil {
			return errutil.Wrapf(err, "decoding certificate")
		}
		log.Println("Certificate found")
		publicKey, ok := cert.PublicKey.(crypto.PublicKey)
		if !ok {
			return errutil.New("invalid public key")
		}

		// Check the signature
		valid, err := VerifySignature(
			publicKey,
			pubkey.KeyType(alg),
			signature,
			a.ClientDataJSON,
			attestationObj.AuthData,
		)
		if err != nil {
			return errutil.Wrapf(err, "verifying signature")
		}
		if !valid {
			return errutil.Wrap(errs.ErrSignatureMismatch)
		}

		// Verify the certificate
		// https://www.w3.org/TR/webauthn-2/#sctn-defined-attestation-formats

		// Enforce packed attestation certificate requirements
		// https://www.w3.org/TR/webauthn-2/#sctn-packed-attestation-cert-requirements
		if !slices.Contains(cert.Subject.OrganizationalUnit, "Authenticator Attestation") {
			return errutil.New("invalid certificate Subject-OU")
		}

		// If attestnCert contains an extension with OID 1.3.6.1.4.1.45724.1.1.4 (id-fido-gen-ce-aaguid) verify
		// that the value of this extension matches the aaguid in authenticatorData.
		for _, ext := range cert.Extensions {
			if ext.Id.Equal(CertExtID_FidoGenCEAAGUID) {
				if ext.Critical {
					return errutil.New("certificate aaguid extension is critical")
				}
				var valueOctetString []byte
				if _, err := asn1.Unmarshal(ext.Value, &valueOctetString); err != nil {
					return errutil.Wrapf(err, "decoding certificate aaguid extension")
				}
				if !slices.Equal(valueOctetString, authData.AttestedCredential.AAGUID[:]) {
					return errutil.New("invalid certificate AAGUID")
				}
			}
		}

		// Optionally, inspect x5c and consult externally provided knowledge to determine whether attStmt conveys
		// a Basic or AttCA attestation.

		return nil
	} else {
		// Verify that the algorithm matches the algorithm on the credential
		if authData.AttestedCredential.CredPublicKeyType != pubkey.KeyType(alg) {
			return errutil.Newf("algorithm mismatch: %d != %d", authData.AttestedCredential.CredPublicKeyType, alg)
		}

		// Check the signature
		valid, err := VerifySignature(
			authData.AttestedCredential.CredPublicKey,
			authData.AttestedCredential.CredPublicKeyType,
			signature,
			a.ClientDataJSON,
			attestationObj.AuthData,
		)
		if err != nil {
			return errutil.Wrapf(err, "verifying signature")
		}
		if !valid {
			return errutil.Wrap(errs.ErrSignatureMismatch)
		}
		return nil
	}
}
