//https://github.com/obscuren/ecies
//https://github.com/ethereum/go-ethereum/blob/master/crypto/ecies/ecies.go
package subtle

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
	"io"
	"math/big"
)

var (
	ErrImport                     = fmt.Errorf("ecies: failed to import key")
	ErrInvalidCurve               = fmt.Errorf("ecies: invalid elliptic curve")
	ErrInvalidParams              = fmt.Errorf("ecies: invalid ECIES parameters")
	ErrInvalidPublicKey           = fmt.Errorf("ecies: invalid public key")
	ErrSharedKeyIsPointAtInfinity = fmt.Errorf("ecies: shared key is point at infinity")
	ErrSharedKeyTooBig            = fmt.Errorf("ecies: shared key params are too big")
)

// PublicKey is a representation of an elliptic curve public key.
type PublicKey struct {
	X *big.Int
	Y *big.Int
	elliptic.Curve
	Params *ECIESParams
}

// Export an ECIES public key as an ECDSA public key.
func (pub *PublicKey) ExportECDSA() *ecdsa.PublicKey {
	return &ecdsa.PublicKey{pub.Curve, pub.X, pub.Y}
}

// Import an ECDSA public key as an ECIES public key.
func ImportECDSAPublic(pub *ecdsa.PublicKey) *PublicKey {
	return &PublicKey{
		X:      pub.X,
		Y:      pub.Y,
		Curve:  pub.Curve,
		Params: ParamsFromCurve(pub.Curve),
	}
}

// PrivateKey is a representation of an elliptic curve private key.
type PrivateKey struct {
	PublicKey
	D *big.Int
}

// Export an ECIES private key as an ECDSA private key.
func (prv *PrivateKey) ExportECDSA() *ecdsa.PrivateKey {
	pub := &prv.PublicKey
	pubECDSA := pub.ExportECDSA()
	return &ecdsa.PrivateKey{*pubECDSA, prv.D}
}

// Import an ECDSA private key as an ECIES private key.
func ImportECDSA(prv *ecdsa.PrivateKey) *PrivateKey {
	pub := ImportECDSAPublic(&prv.PublicKey)
	return &PrivateKey{*pub, prv.D}
}

// Generate an elliptic curve public / private keypair. If params is nil,
// the recommended default paramters for the key will be chosen.
func GenerateKey(rand io.Reader, curve elliptic.Curve, params *ECIESParams) (prv *PrivateKey, err error) {
	pb, x, y, err := elliptic.GenerateKey(curve, rand)
	if err != nil {
		return
	}
	prv = new(PrivateKey)
	prv.PublicKey.X = x
	prv.PublicKey.Y = y
	prv.PublicKey.Curve = curve
	prv.D = new(big.Int).SetBytes(pb)
	if params == nil {
		params = ParamsFromCurve(curve)
	}
	prv.PublicKey.Params = params
	return
}

// MaxSharedKeyLength returns the maximum length of the shared key the
// public key can produce.
func MaxSharedKeyLength(pub *PublicKey) int {
	return (pub.Curve.Params().BitSize + 7) / 8
}

// ECDH key agreement method used to establish secret keys for encryption.
func (prv *PrivateKey) GenerateShared(pub *PublicKey, skLen, macLen int) (sk []byte, err error) {
	if prv.PublicKey.Curve != pub.Curve {
		return nil, ErrInvalidCurve
	}
	if skLen+macLen > MaxSharedKeyLength(pub) {
		return nil, ErrSharedKeyTooBig
	}
	x, _ := pub.Curve.ScalarMult(pub.X, pub.Y, prv.D.Bytes())
	if x == nil {
		return nil, ErrSharedKeyIsPointAtInfinity
	}

	sk = make([]byte, skLen+macLen)
	skBytes := x.Bytes()
	copy(sk[len(sk)-len(skBytes):], skBytes)
	return sk, nil
}

var (
	ErrKeyDataTooLong = fmt.Errorf("ecies: can't supply requested key data")
	ErrSharedTooLong  = fmt.Errorf("ecies: shared secret is too long")
	ErrInvalidMessage = fmt.Errorf("ecies: invalid message")
)

var (
	big2To32   = new(big.Int).Exp(big.NewInt(2), big.NewInt(32), nil)
	big2To32M1 = new(big.Int).Sub(big2To32, big.NewInt(1))
)

// The default curve for this package is the NIST P256 curve, which
// provides security equivalent to AES-128.
var DefaultCurve = elliptic.P256()

var (
	ErrUnsupportedECDHAlgorithm   = fmt.Errorf("ecies: unsupported ECDH algorithm")
	ErrUnsupportedECIESParameters = fmt.Errorf("ecies: unsupported ECIES parameters")
)

type ECIESParams struct {
	Hash      func() hash.Hash // hash function
	hashAlgo  crypto.Hash
	Cipher    func([]byte) (cipher.Block, error) // symmetric cipher
	BlockSize int                                // block size of symmetric cipher
	KeyLen    int                                // length of symmetric key
}

// Standard ECIES parameters:
// * ECIES using AES128 and HMAC-SHA-256-16
// * ECIES using AES256 and HMAC-SHA-256-32
// * ECIES using AES256 and HMAC-SHA-384-48
// * ECIES using AES256 and HMAC-SHA-512-64

var (
	ECIES_AES128_SHA256 = &ECIESParams{
		Hash:      sha256.New,
		hashAlgo:  crypto.SHA256,
		Cipher:    aes.NewCipher,
		BlockSize: aes.BlockSize,
		KeyLen:    16,
	}

	ECIES_AES256_SHA256 = &ECIESParams{
		Hash:      sha256.New,
		hashAlgo:  crypto.SHA256,
		Cipher:    aes.NewCipher,
		BlockSize: aes.BlockSize,
		KeyLen:    32,
	}

	ECIES_AES256_SHA384 = &ECIESParams{
		Hash:      sha512.New384,
		hashAlgo:  crypto.SHA384,
		Cipher:    aes.NewCipher,
		BlockSize: aes.BlockSize,
		KeyLen:    32,
	}

	ECIES_AES256_SHA512 = &ECIESParams{
		Hash:      sha512.New,
		hashAlgo:  crypto.SHA512,
		Cipher:    aes.NewCipher,
		BlockSize: aes.BlockSize,
		KeyLen:    32,
	}
)

var paramsFromCurve = map[elliptic.Curve]*ECIESParams{
	elliptic.P256(): ECIES_AES128_SHA256,
	elliptic.P384(): ECIES_AES256_SHA384,
	elliptic.P521(): ECIES_AES256_SHA512,
}

func AddParamsForCurve(curve elliptic.Curve, params *ECIESParams) {
	paramsFromCurve[curve] = params
}

// ParamsFromCurve selects parameters optimal for the selected elliptic curve.
// Only the curves P256, P384, and P512 are supported.
func ParamsFromCurve(curve elliptic.Curve) (params *ECIESParams) {
	return paramsFromCurve[curve]
}

// ASN.1 encode the ECIES parameters relevant to the encryption operations.
func paramsToASNECIES(params *ECIESParams) (asnParams asnECIESParameters) {
	if nil == params {
		return
	}
	asnParams.KDF = asnNISTConcatenationKDF
	asnParams.MAC = hmacFull
	switch params.KeyLen {
	case 16:
		asnParams.Sym = aes128CTRinECIES
	case 24:
		asnParams.Sym = aes192CTRinECIES
	case 32:
		asnParams.Sym = aes256CTRinECIES
	}
	return
}

// ASN.1 encode the ECIES parameters relevant to ECDH.
func paramsToASNECDH(params *ECIESParams) (algo asnECDHAlgorithm) {
	switch params.hashAlgo {
	case crypto.SHA224:
		algo = dhSinglePass_stdDH_sha224kdf
	case crypto.SHA256:
		algo = dhSinglePass_stdDH_sha256kdf
	case crypto.SHA384:
		algo = dhSinglePass_stdDH_sha384kdf
	case crypto.SHA512:
		algo = dhSinglePass_stdDH_sha512kdf
	}
	return
}

// ASN.1 decode the ECIES parameters relevant to the encryption stage.
func asnECIEStoParams(asnParams asnECIESParameters, params *ECIESParams) {
	if !asnParams.KDF.Cmp(asnNISTConcatenationKDF) {
		params = nil
		return
	} else if !asnParams.MAC.Cmp(hmacFull) {
		params = nil
		return
	}

	switch {
	case asnParams.Sym.Cmp(aes128CTRinECIES):
		params.KeyLen = 16
		params.BlockSize = 16
		params.Cipher = aes.NewCipher
	case asnParams.Sym.Cmp(aes192CTRinECIES):
		params.KeyLen = 24
		params.BlockSize = 16
		params.Cipher = aes.NewCipher
	case asnParams.Sym.Cmp(aes256CTRinECIES):
		params.KeyLen = 32
		params.BlockSize = 16
		params.Cipher = aes.NewCipher
	default:
		params = nil
	}
}

// ASN.1 decode the ECIES parameters relevant to ECDH.
func asnECDHtoParams(asnParams asnECDHAlgorithm, params *ECIESParams) {
	if asnParams.Cmp(dhSinglePass_stdDH_sha224kdf) {
		params.hashAlgo = crypto.SHA224
		params.Hash = sha256.New224
	} else if asnParams.Cmp(dhSinglePass_stdDH_sha256kdf) {
		params.hashAlgo = crypto.SHA256
		params.Hash = sha256.New
	} else if asnParams.Cmp(dhSinglePass_stdDH_sha384kdf) {
		params.hashAlgo = crypto.SHA384
		params.Hash = sha512.New384
	} else if asnParams.Cmp(dhSinglePass_stdDH_sha512kdf) {
		params.hashAlgo = crypto.SHA512
		params.Hash = sha512.New
	} else {
		params = nil
	}
}
