package paymentmethodtokengo

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"

	"github.com/google/tink/go/subtle/ecies"
	"github.com/google/tink/go/subtle/mac"
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

func (g *GooglePayTokenRecipient) Unseal(resp GooglePayTokenResponse) (*string, error) {
	err := g.Verify(resp)
	if err != nil {
		return nil, err
	}
	signedMessage := SignedMessage{}
	err = json.Unmarshal([]byte(resp.SignedMessageStr), &signedMessage)
	if err != nil {
		return nil, err
	}

	googlePayConstants := getConstants()

	merchantPrivateKey, err := ParsePrivateKey(g.RecipientPrivateKey)
	if err != nil {
		return nil, err
	}

	eciesHkdf := ecies.EciesHkdfRecipientKem{*merchantPrivateKey}
	if err != nil {
		return nil, err
	}
	kem, err := base64.StdEncoding.DecodeString(signedMessage.EphemeralPublicKey)
	if err != nil {
		return nil, err
	}

	key, err := eciesHkdf.GenerateKey(kem,
		googlePayConstants.HMAC_SHA256_ALGO,
		googlePayConstants.HKDF_EMPTY_SALT,
		googlePayConstants.GOOGLE_CONTEXT_INFO_ECV1,
		googlePayConstants.AES_CTR_KEY_SIZE,
		googlePayConstants.HMAC_SHA256_KEY_SIZE)
	if err != nil {
		return nil, err
	}
	hmacSha256Key := key[googlePayConstants.AES_CTR_KEY_SIZE:]
	encryptedMessage, err := base64.StdEncoding.DecodeString(signedMessage.EncryptedMessage)
	if err != nil {
		return nil, err
	}

	expectedTag, err := base64.StdEncoding.DecodeString(signedMessage.Tag)
	if err != nil {
		return nil, err
	}

	hmac, err := mac.NewHmac("SHA256", hmacSha256Key, uint32(len(expectedTag)))
	if err != nil {
		return nil, err
	}

	computedTag, err := hmac.ComputeMac(encryptedMessage)

	if err != nil {
		return nil, err
	}

	if !bytes.Equal(expectedTag, computedTag) {
		return nil, errors.New("MAC tag was not verified")
	}

	aesCTRKey := key[:googlePayConstants.AES_CTR_KEY_SIZE]

	block, err := aes.NewCipher(aesCTRKey)
	if err != nil {
		return nil, err
	}

	stream := cipher.NewCTR(block, googlePayConstants.AES_CTR_ALGO_IV)
	decryptedMessageBytes := make([]byte, len(encryptedMessage))

	stream.XORKeyStream(decryptedMessageBytes, encryptedMessage)

	decryptedMessage := string(decryptedMessageBytes)
	return &decryptedMessage, nil
}

func (g *GooglePayTokenRecipient) Decrypt(resp GooglePayTokenResponse) error {
	return nil
}

//Verify
func (g *GooglePayTokenRecipient) Verify(resp GooglePayTokenResponse) error {
	toVerify := g.generateToVerify(resp)

	signatureBytes, err := base64.StdEncoding.DecodeString(resp.Signature)
	if err != nil {
		return err
	}

	x, y, err := DecodePublicKey(g.KeyMananger.CurrentKeys.Keys[0].KeyValue)

	publicKey := ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}

	verifier, err := signature.NewEcdsaVerifyFromPublicKey("SHA256", "DER", &publicKey)
	if err != nil {
		return err
	}

	err = verifier.Verify(signatureBytes, toVerify)
	if err != nil {
		return err
	}
	return nil
}
