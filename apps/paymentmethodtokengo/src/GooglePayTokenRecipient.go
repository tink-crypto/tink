package paymentmethodtoken

import (
	"crypto/ecdsa"
	"crypto/elliptic"
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
	MessageId            string `json:"messageId"`
	PaymentMethod        string `json:"paymentMethod"`
	PaymentMethodDetails string `json:'paymentMethodDetails'`
	Card                 struct {
		PAN             string `json:"pan"`
		ExpirationMonth string `json:"expirationMonth"`
		ExpirationYear  string `json:"expirationYear"`
	} `json:"PaymentMethodDetails"`
}

type GooglePayTokenRecipient struct {
	RecipientId         string
	RecipientPrivateKey ecdsa.PrivateKey
	keyMananger         GooglePaymentsPublicKeyManager
	Constants           GooglePayConstants
}

func (g *GooglePayTokenRecipient) generateECKey() string {
	curve := elliptic.P256()

	return "test"
}
