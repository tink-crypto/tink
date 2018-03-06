package paymentmethodtoken

import (
	"crypto/ecdsa"
	"crypto/x509"

	"github.com/google/tink/go/subtle/signature"
)

type GooglePayTokenResponse struct {
	ProtocolVersion string `json:"protocolVersion"`
	Signature       string `json:"signature"`
	SignedMessage   struct {
		EncryptedMessage   string `json:"encryptedMessage"`
		EphemeralPublicKey string `json:"ephemeralPublicKey"`
		Tag                string `json:"tag"`
	} `json:"signedMessage"`
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

func (g *GooglePayTokenRecipient) generateSignedMessage(resp GooglePayTokenResponse) []byte {
	return make([]byte, 100)
}

func (g *GooglePayTokenRecipient) Unseal(resp GooglePayTokenResponse) error {
	signedMessage := g.generateSignedMessage(resp)
	err := g.Verify(signedMessage, []byte(resp.SignedMessage.EncryptedMessage))
	if err != nil {
		return err
	}

	return nil
}

func (g *GooglePayTokenRecipient) Verify(signatureBytes []byte, signedMessage []byte) error {
	keyData, err := x509.ParsePKIXPublicKey([]byte(g.KeyMananger.CurrentKeys.Keys[0].KeyValue)) //TODO:this is ugly
	publicKey := keyData.(*ecdsa.PublicKey)
	verifier, err := signature.NewEcdsaVerifyFromPublicKey("SHA256", "DER", publicKey)
	if err != nil {
		return err
	}
	err = verifier.Verify(signatureBytes, signedMessage)
	if err != nil {
		return err
	}
	return nil
}
