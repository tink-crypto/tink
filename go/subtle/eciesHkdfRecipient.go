package subtle

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"hash"

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

func (e *EciesHkdfRecipientKem) GenerateKey(kem *ecdsa.PublicKey, hmacAlgo string, hkdfSalt []byte, hkdfInfo []byte, symKeySize int, macKeySize int) ([]byte, error) {
	eciesEphemeralPublicKey := ecies.ImportECDSAPublic(kem)
	eciesPrivateKey := ecies.ImportECDSA(&e.PrivateKey)
	sharedSecret, err := eciesPrivateKey.GenerateShared(eciesEphemeralPublicKey, symKeySize, macKeySize)
	if err != nil {
		return nil, err
	}
	concatSecretPrivKey := append(sharedSecret, eciesPrivateKey.D.Bytes()...)
	keyReader := hkdf.New(getAlgorithm(hmacAlgo), concatSecretPrivKey, hkdfSalt, hkdfInfo)
	key := make([]byte, 256)
	_, err = keyReader.Read(key)
	return key, err
}
