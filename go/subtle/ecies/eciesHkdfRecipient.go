package ecies

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"hash"
	"math/big"

	"github.com/obscuren/ecies" //tink has no good golang library for this.
	"golang.org/x/crypto/hkdf"
)

/** EciesHkdfRecipientKem is more or less cloned from the java class
HKDF-based KEM (key encapsulation mechanism) for ECIES recipient
**/
type EciesHkdfRecipientKem struct {
	PrivateKey ecdsa.PrivateKey
}

func getAlgorithm(hmacAlgo string) func() hash.Hash {
	if hmacAlgo == "HmacSha256" {
		return sha256.New
	} else {
		return nil
	}
}

/** generateKey
This is the key derivation function for eciesHkdf
kem is the base64 decoded ephemeralPublicKey byte array representation
hmacAlgo is a string which represents the hash message authentication algorithm (only HmacSha256 supported for now)
hkdfSalt is salt for Algorithm
hkdfInfo is the data to be checked
symKeySize is the size of the symmetricKey we used
macKeySize is the size of the MAC key
*/
func (e *EciesHkdfRecipientKem) GenerateKey(kem []byte, hmacAlgo string, hkdfSalt []byte, hkdfInfo []byte, symKeySize int, macKeySize int) ([]byte, error) {
	x := big.Int{}
	x.SetBytes(kem[1:33])
	y := big.Int{}
	y.SetBytes(kem[33:65])
	ephemeralPublicKey := ecdsa.PublicKey{e.PrivateKey.Curve, &x, &y}
	eciesEphemeralPublicKey := ecies.ImportECDSAPublic(&ephemeralPublicKey)
	eciesPrivateKey := ecies.ImportECDSA(&e.PrivateKey)
	sharedSecret, err := eciesPrivateKey.GenerateShared(eciesEphemeralPublicKey, symKeySize, macKeySize)
	if err != nil {
		return nil, err
	}
	concatSecretPrivKey := append(kem, sharedSecret...)
	keyReader := hkdf.New(getAlgorithm(hmacAlgo), concatSecretPrivKey, hkdfSalt, hkdfInfo)
	key := make([]byte, symKeySize+macKeySize)
	_, err = keyReader.Read(key)
	return key, err
}
