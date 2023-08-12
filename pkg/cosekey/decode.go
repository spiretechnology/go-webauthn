package cosekey

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"fmt"
	"math/big"

	"github.com/fxamacker/cbor/v2"
	"github.com/spiretechnology/go-webauthn/internal/errutil"
	"github.com/spiretechnology/go-webauthn/pkg/pubkey"
)

type COSEKey struct {
	PublicKey crypto.PublicKey
	KeyType   pubkey.KeyType
}

func DecodeCOSEPublicKey(data []byte) (*COSEKey, error) {
	var coseKey map[int]any
	if err := cbor.Unmarshal(data, &coseKey); err != nil {
		return nil, errutil.Wrapf(err, "unmarshaling COSE key")
	}

	// Extract the key type (kty)
	kty, ok := coseKey[1].(uint64)
	if !ok {
		return nil, errutil.New("missing or invalid kty")
	}

	// Decode the key based on the type
	switch kty {
	case 2:
		return decodeEC2Key(coseKey)
	case 3:
		return decodeRSAKey(coseKey)
	default:
		return nil, errutil.Newf("unsupported kty: %d", kty)
	}
}

var ec2Curves = map[uint64]elliptic.Curve{
	1: elliptic.P256(),
	2: elliptic.P384(),
	3: elliptic.P521(),
}

func decodeEC2Key(coseKey map[int]any) (*COSEKey, error) {
	// Get the curve identifier
	crv, ok := coseKey[-1].(uint64)
	if !ok {
		return nil, errutil.New("missing or invalid crv for EC2 key")
	}

	// Select the curve based on the value
	curve, ok := ec2Curves[crv]
	if !ok {
		return nil, errutil.Newf("unsupported crv: %d", crv)
	}

	// Get the X and Y coordinates
	xBytes, ok := coseKey[-2].([]byte)
	if !ok {
		return nil, fmt.Errorf("missing or invalid x coordinate for EC2 key")
	}
	yBytes, ok := coseKey[-3].([]byte)
	if !ok {
		return nil, fmt.Errorf("missing or invalid y coordinate for EC2 key")
	}

	// Get the key type
	keyType, ok := coseKey[3].(int64)
	if !ok {
		return nil, errutil.New("missing or invalid key type for EC2 key")
	}

	return &COSEKey{
		PublicKey: &ecdsa.PublicKey{
			Curve: curve,
			X:     new(big.Int).SetBytes(xBytes),
			Y:     new(big.Int).SetBytes(yBytes),
		},
		KeyType: pubkey.KeyType(keyType),
	}, nil
}

func decodeRSAKey(coseKey map[int]any) (*COSEKey, error) {
	// Get the modulus and exponent
	nBytes, ok := coseKey[-1].([]byte)
	if !ok {
		return nil, fmt.Errorf("missing or invalid n for RSA key")
	}
	eBytes, ok := coseKey[-2].([]byte)
	if !ok {
		return nil, fmt.Errorf("missing or invalid e for RSA key")
	}

	// Get the key type
	keyType, ok := coseKey[3].(int64)
	if !ok {
		return nil, errutil.New("missing or invalid key type for RSA key")
	}

	return &COSEKey{
		PublicKey: &rsa.PublicKey{
			N: new(big.Int).SetBytes(nBytes),
			E: int(new(big.Int).SetBytes(eBytes).Int64()),
		},
		KeyType: pubkey.KeyType(keyType),
	}, nil
}
