//https://github.com/obscuren/ecies (taken from go-ethereum)
// See conditions and license on:
//https://github.com/ethereum/go-ethereum/blob/master/crypto/ecies/ecies.go
package subtle

import (
	"crypto/elliptic"
	"errors"
	"io"
	"math/big"
)

type EllipticPublicKey struct {
	X, Y  *big.Int
	Curve elliptic.Curve
}

type EllipticPrivateKey struct {
	D *big.Int
	EllipticPublicKey
}

// The default curve for this package is the NIST P256 curve, which
// provides security equivalent to AES-128.
var DefaultCurve = elliptic.P256()

// Generate an elliptic curve public / private keypair. If params is nil,
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

// ECDH key agreement method used to establish secret keys for encryption.
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
