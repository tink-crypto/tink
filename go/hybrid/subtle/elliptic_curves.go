// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

package subtle

import (
	"bytes"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
)

// ECPublicKey represents a elliptic curve public key.
type ECPublicKey struct {
	elliptic.Curve
	Point ECPoint
}

// ECPrivateKey represents a elliptic curve public key.
type ECPrivateKey struct {
	PublicKey ECPublicKey
	D         *big.Int
}

// GetECPrivateKey converts a stored private key to ECPrivateKey.
func GetECPrivateKey(c elliptic.Curve, b []byte) *ECPrivateKey {
	d := new(big.Int)
	d.SetBytes(b)

	x, y := c.Params().ScalarBaseMult(b)
	pub := ECPublicKey{
		Curve: c,
		Point: ECPoint{
			X: x,
			Y: y,
		},
	}
	return &ECPrivateKey{
		PublicKey: pub,
		D:         d,
	}

}

// ECPoint represents a point on the elliptic curve.
type ECPoint struct {
	X, Y *big.Int
}

func (p *ECPrivateKey) getParams() *elliptic.CurveParams {
	return p.PublicKey.Curve.Params()
}

func getModulus(c elliptic.Curve) *big.Int {
	return c.Params().P
}

func fieldSizeInBits(c elliptic.Curve) int {
	t := big.NewInt(1)
	r := t.Sub(getModulus(c), t)
	return r.BitLen()
}

func fieldSizeInBytes(c elliptic.Curve) int {
	return (fieldSizeInBits(c) + 7) / 8
}

func encodingSizeInBytes(c elliptic.Curve, p string) (int, error) {
	cSize := fieldSizeInBytes(c)
	switch p {
	case "UNCOMPRESSED":
		return 2*cSize + 1, nil
	case "DO_NOT_USE_CRUNCHY_UNCOMPRESSED":
		return 2 * cSize, nil
	case "COMPRESSED":
		return cSize + 1, nil
	}
	return 0, fmt.Errorf("invalid point format :%s", p)

}

// PointEncode encodes a point into the format specified.
func PointEncode(c elliptic.Curve, pFormat string, pt ECPoint) ([]byte, error) {
	if !c.IsOnCurve(pt.X, pt.Y) {
		return nil, errors.New("curve check failed")
	}
	cSize := fieldSizeInBytes(c)
	y := pt.Y.Bytes()
	x := pt.X.Bytes()
	switch pFormat {
	case "UNCOMPRESSED":
		encoded := make([]byte, 2*cSize+1)
		copy(encoded[1+2*cSize-len(y):], y)
		copy(encoded[1+cSize-len(x):], x)
		encoded[0] = 4
		return encoded, nil
	case "DO_NOT_USE_CRUNCHY_UNCOMPRESSED":
		encoded := make([]byte, 2*cSize)
		if len(x) > cSize {
			x = bytes.Replace(x, []byte("\x00"), []byte{}, -1)
		}
		if len(y) > cSize {
			y = bytes.Replace(y, []byte("\x00"), []byte{}, -1)
		}
		copy(encoded[2*cSize-len(y):], y)
		copy(encoded[cSize-len(x):], x)
		return encoded, nil
	case "COMPRESSED":
		encoded := make([]byte, cSize+1)
		copy(encoded[1+cSize-len(x):], x)
		encoded[0] = 2
		if pt.Y.Bit(0) > 0 {
			encoded[0] = 3
		}
		return encoded, nil
	}
	return nil, errors.New("invalid point format")

}

// PointDecode decodes a encoded point to return an ECPoint
func PointDecode(c elliptic.Curve, pFormat string, e []byte) (*ECPoint, error) {
	cSize := fieldSizeInBytes(c)
	x, y := new(big.Int), new(big.Int)
	switch pFormat {
	case "UNCOMPRESSED":
		if len(e) != (2*cSize + 1) {
			return nil, errors.New("invalid point size")
		}
		if e[0] != 4 {
			return nil, errors.New("invalid point format")
		}
		x.SetBytes(e[1 : cSize+1])
		y.SetBytes(e[cSize+1:])
		if !c.IsOnCurve(x, y) {
			return nil, errors.New("invalid point")
		}
		return &ECPoint{
			X: x,
			Y: y,
		}, nil
	case "DO_NOT_USE_CRUNCHY_UNCOMPRESSED":
		if len(e) != 2*cSize {
			return nil, errors.New("invalid point size")
		}
		x.SetBytes(e[:cSize])
		y.SetBytes(e[cSize:])
		if !c.IsOnCurve(x, y) {
			return nil, errors.New("invalid point")
		}
		return &ECPoint{
			X: x,
			Y: y,
		}, nil
	case "COMPRESSED":
		if len(e) != cSize+1 {
			return nil, errors.New("compressed point has wrong length")
		}
		lsb := false
		if e[0] == 2 {
			lsb = false
		} else if e[0] == 3 {
			lsb = true
		} else {
			return nil, errors.New("invalid format")
		}
		x := new(big.Int)
		x.SetBytes(e[1:])
		if (x.Sign() == -1) || (x.Cmp(c.Params().P) != -1) {
			return nil, errors.New("x is out of range")
		}
		y := getY(x, lsb, c)
		return &ECPoint{
			X: x,
			Y: y,
		}, nil
	}
	return nil, fmt.Errorf("invalid format: %s", pFormat)
}

func getY(x *big.Int, lsb bool, c elliptic.Curve) *big.Int {
	// y² = x³ - 3x + b
	x3 := new(big.Int).Mul(x, x)
	x3.Mul(x3, x)

	threeX := new(big.Int).Lsh(x, 1)
	threeX.Add(threeX, x)
	b := c.Params().B
	p := c.Params().P

	x3.Sub(x3, threeX)
	x3.Add(x3, b)
	x3.ModSqrt(x3, p)
	e := uint(1)
	if lsb {
		e = 0
	}
	if e == x3.Bit(0) {
		x3 := x3.Sub(p, x3)
		x3.Mod(x3, p)
	}
	return x3
}

func validatePublicPoint(pub *ECPoint, priv *ECPrivateKey) error {
	if priv.PublicKey.Curve.IsOnCurve(pub.X, pub.Y) {
		return nil
	}
	return errors.New("invalid public key")
}

// ComputeSharedSecret is used to compute a shared secret using given private key and peer public key.
func ComputeSharedSecret(pub *ECPoint, priv *ECPrivateKey) ([]byte, error) {
	if err := validatePublicPoint(pub, priv); err != nil {
		return nil, err
	}

	x, y := priv.PublicKey.Curve.ScalarMult(pub.X, pub.Y, priv.D.Bytes())

	if x == nil {
		return nil, errors.New("shared key compute error")
	}
	// check if x,y are on the curve
	if err := validatePublicPoint(&ECPoint{X: x, Y: y}, priv); err != nil {
		return nil, errors.New("invalid shared key")
	}

	sharedSecret := make([]byte, maxSharedKeyLength(priv.PublicKey))
	xBytes := x.Bytes()
	copy(sharedSecret[len(sharedSecret)-len(xBytes):], xBytes)
	return sharedSecret, nil
}

func maxSharedKeyLength(pub ECPublicKey) int {
	return (pub.Curve.Params().BitSize + 7) / 8
}

// GenerateECDHKeyPair will create a new private key for a given curve.
func GenerateECDHKeyPair(c elliptic.Curve) (*ECPrivateKey, error) {
	p, x, y, err := elliptic.GenerateKey(c, rand.Reader)
	if err != nil {
		return nil, err
	}
	return &ECPrivateKey{
		PublicKey: ECPublicKey{
			Curve: c,
			Point: ECPoint{
				X: x,
				Y: y,
			},
		},
		D: new(big.Int).SetBytes(p),
	}, nil

}

// GetCurve returns the elliptic.Curve for a given standard curve name.
func GetCurve(c string) (elliptic.Curve, error) {
	switch c {
	case "secp224r1", "NIST_P224", "P-224":
		return elliptic.P224(), nil
	case "secp256r1", "NIST_P256", "P-256", "EllipticCurveType_NIST_P256":
		return elliptic.P256(), nil
	case "secp384r1", "NIST_P384", "P-384", "EllipticCurveType_NIST_P384":
		return elliptic.P384(), nil
	case "secp521r1", "NIST_P521", "P-521", "EllipticCurveType_NIST_P521":
		return elliptic.P521(), nil
	default:
		return nil, errors.New("unsupported curve")
	}
}
