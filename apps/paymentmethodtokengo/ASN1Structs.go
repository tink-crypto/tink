package paymentmethodtokengo

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"math/big"
)

// Asn1Asn1GooglePublicKey
// This is the structure of the Google Public key which we asn1 unmarshal into
// Bits contains 0x04 followed by 32 bits of x and 32 bits of y
type Asn1GooglePublicKey struct {
	Metadata struct {
		KeyType   asn1.ObjectIdentifier
		CurveType asn1.ObjectIdentifier
	}
	Bits asn1.BitString
}

// DecodePublicKey base64 decodes and unmarshals to get x and y
func DecodePublicKey(keyVal string) (*big.Int, *big.Int, error) {
	bytesToUnmarshal, err := base64.StdEncoding.DecodeString(keyVal)
	if err != nil {
		return nil, nil, err
	}

	key := Asn1GooglePublicKey{}
	_, err = asn1.Unmarshal(bytesToUnmarshal, &key)
	if err != nil {
		return nil, nil, err
	}

	x := new(big.Int)
	x.SetBytes(key.Bits.Bytes[1:33])
	y := new(big.Int)
	y.SetBytes(key.Bits.Bytes[33:65])

	return x, y, nil
}

func ParsePrivateKey(keyVal string) (*ecdsa.PrivateKey, error) {
	keyBytes, err := base64.StdEncoding.DecodeString(keyVal)
	if err != nil {
		return nil, err
	}

	keyStruct, err := x509.ParsePKCS8PrivateKey(keyBytes)
	if err != nil {
		return nil, err
	}

	privKey := keyStruct.(*ecdsa.PrivateKey)

	return privKey, nil
}
