package paymentmethodtoken

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/binary"

	"github.com/google/tink/go/subtle/signature"
)

type GooglePayTokenResponse struct {
	ProtocolVersion  string `json:"protocolVersion"`
	Signature        string `json:"signature"`
	SignedMessageStr string `json:"signedMessage"`
}

type SignedMessage struct {
	EncryptedMessage   string `json:"encryptedMessage"`
	EphemeralPublicKey string `json:"ephemeralPublicKey"`
	Tag                string `json:"tag"`
}

type DecryptedMessage struct {
	MessageExpiration    string `json:"messageExpiration"`
	MessageID            string `json:"messageId"`
	PaymentMethod        string `json:"paymentMethod"`
	PaymentMethodDetails string `json:"paymentMethodDetails"`
	Card                 struct {
		PAN             string `json:"pan"`
		ExpirationMonth string `json:"expirationMonth"`
		ExpirationYear  string `json:"expirationYear"`
	} `json:"PaymentMethodDetails"`
}

type GooglePayTokenRecipient struct {
	RecipientID         string
	RecipientPrivateKey string
	KeyMananger         GooglePaymentsPublicKeyManager
	Constants           GooglePayConstants
}

func (g *GooglePayTokenRecipient) GenerateECKey() string {
	return "test"
}

func (g *GooglePayTokenRecipient) generateToVerify(resp GooglePayTokenResponse) []byte {
	toConvert := []string{"Google", g.RecipientID, "ECv1", resp.SignedMessageStr} //Order matters
	toReturn := make([]byte, 0)
	for i := 0; i < len(toConvert); i++ {
		bytesLength := make([]byte, 4)
		binary.LittleEndian.PutUint32(bytesLength, uint32(len(toConvert[i])))
		toReturn = append(toReturn, bytesLength...)
		toReturn = append(toReturn, []byte(toConvert[i])...)
	}
	return toReturn
}

func (g *GooglePayTokenRecipient) Unseal(resp GooglePayTokenResponse) error {
	err := g.Verify(resp)
	if err != nil {
		return err
	}

	return nil
}

//Verify
func (g *GooglePayTokenRecipient) Verify(resp GooglePayTokenResponse) error {
	toVerify := g.generateToVerify(resp)
	signatureBytes := []byte(resp.Signature)
	keyData, err := x509.ParsePKIXPublicKey([]byte(g.KeyMananger.CurrentKeys.Keys[0].KeyValue)) //TODO:this is ugly
	if err != nil {
		return err
	}
	publicKey := keyData.(*ecdsa.PublicKey)
	verifier, err := signature.NewEcdsaVerifyFromPublicKey("SHA256", "DER", publicKey)
	if err != nil {
		return err
	}
	err = verifier.Verify(signatureBytes, toVerify)
	if err != nil {
		return err
	}
	return nil
}
