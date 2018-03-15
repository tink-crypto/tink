package hybrid

import (
	"math/big"

	"github.com/google/tink/go/subtle"
	"golang.org/x/crypto/hkdf"
	//tink has no good golang library for this.
)

/** EciesHkdfRecipientKem is more or less cloned from the java class
HKDF-based KEM (key encapsulation mechanism) for ECIES recipient
**/
type EciesHkdfRecipientKem struct {
	Priv subtle.EllipticPrivateKey
}

/** GenerateKey is the key derivation function
 */
func (e *EciesHkdfRecipientKem) GenerateKey(kem []byte, hashAlgo string, hkdfSalt []byte, hkdfInfo []byte, symKeySize int, macKeySize int) ([]byte, error) {
	x := big.Int{}
	x.SetBytes(kem[1:33])
	y := big.Int{}
	y.SetBytes(kem[33:65])
	ephemeralPublicKey := subtle.EllipticPublicKey{
		Curve: e.Priv.Curve,
		X:     &x,
		Y:     &y}
	sharedSecret, err := e.Priv.GenerateShared(&ephemeralPublicKey, symKeySize+macKeySize)
	if err != nil {
		return nil, err
	}
	concatSecretPrivKey := append(kem, sharedSecret...)
	keyReader := hkdf.New(subtle.GetHashFunc(hashAlgo), concatSecretPrivKey, hkdfSalt, hkdfInfo)
	key := make([]byte, symKeySize+macKeySize)
	_, err = keyReader.Read(key)
	return key, err
}
