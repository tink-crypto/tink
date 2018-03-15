//https://github.com/obscuren/ecies (taken from go-ethereum)
// See conditions and license on:
//https://github.com/ethereum/go-ethereum/blob/master/crypto/ecies/ecies.go
package subtle

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"io"
	"math/big"
)

//EllipticPublicKey define curve and point
type EllipticPublicKey struct {
	Curve elliptic.Curve
	X, Y  *big.Int
}

//EllipticPrivateKey contains corresponding public key and generator D
type EllipticPrivateKey struct {
	EllipticPublicKey
	D *big.Int
}

// ExportECDSA an ECIES public key as an ECDSA public key.
func (pub *EllipticPublicKey) ExportECDSA() *ecdsa.PublicKey {
	return &ecdsa.PublicKey{pub.Curve, pub.X, pub.Y}
}

// ImportECDSAPublic an ECDSA public key as an ECIES public key.
func ImportECDSAPublic(pub *ecdsa.PublicKey) *EllipticPublicKey {
	return &EllipticPublicKey{
		X:     pub.X,
		Y:     pub.Y,
		Curve: pub.Curve,
	}
}

// ExportECDSA an ECIES private key as an ECDSA private key.
func (prv *EllipticPrivateKey) ExportECDSA() *ecdsa.PrivateKey {
	pub := &prv.EllipticPublicKey
	pubECDSA := pub.ExportECDSA()
	return &ecdsa.PrivateKey{*pubECDSA, prv.D}
}

// ImportECDSA an ECDSA private key as an ECIES private key.
func ImportECDSA(prv *ecdsa.PrivateKey) *EllipticPrivateKey {
	pub := ImportECDSAPublic(&prv.PublicKey)
	return &EllipticPrivateKey{*pub, prv.D}
}

// DefaultCurve for this package is the NIST P256 curve, which
// provides security equivalent to AES-128.
var DefaultCurve = elliptic.P256()

// GenerateKey returns an elliptic curve public / private keypair. If params is nil,
// the recommended default paramters for the key will be chosen.
func GenerateKey(rand io.Reader, curve elliptic.Curve) (prv *EllipticPrivateKey, err error) {
	pb, x, y, err := elliptic.GenerateKey(curve, rand)
	if err != nil {
		return
	}
	prv = new(EllipticPrivateKey)
	prv.EllipticPublicKey.X = x
	prv.EllipticPublicKey.Y = y
	prv.EllipticPublicKey.Curve = curve
	prv.D = new(big.Int).SetBytes(pb)
	return
}

var (
	ErrBadSharedKeys   = errors.New("Curves do not match")
	ErrSharedKeyTooBig = errors.New("Requested invalid key size (too big)")
)

// GenerateShared is part of ECDH key agreement method used to establish secret keys for encryption.
func (prv *EllipticPrivateKey) GenerateShared(pub *EllipticPublicKey, keyLength int) (sk []byte, err error) {
	if prv.EllipticPublicKey.Curve != pub.Curve {
		return nil, ErrBadSharedKeys
	}
	if keyLength > MaxSharedKeyLength(pub) {
		return nil, ErrSharedKeyTooBig
	}
	x, _ := pub.Curve.ScalarMult(pub.X, pub.Y, prv.D.Bytes())
	if x == nil || err != nil {
		return nil, errors.New("Could not generate shared key")
	}

	sk = make([]byte, keyLength)
	skBytes := x.Bytes()
	copy(sk[len(sk)-len(skBytes):], skBytes)
	return sk, nil
}

// MaxSharedKeyLength returns the maximum length of the shared key the
// public key can produce.
func MaxSharedKeyLength(pub *EllipticPublicKey) int {
	return (pub.Curve.Params().BitSize + 7) / 8
}
