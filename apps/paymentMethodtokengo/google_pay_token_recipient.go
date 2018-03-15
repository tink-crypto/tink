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
	"strconv"
	"time"

	"github.com/google/tink/go/subtle"
	"github.com/google/tink/go/subtle/hybrid"
	"github.com/google/tink/go/subtle/mac"
	"github.com/google/tink/go/subtle/signature"
)

var googlePayConstants = getConstants()

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
	RecipientID          string
	RecipientPrivateKeys []string
	KeyMananger          GooglePaymentsPublicKeyManager
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

//Decrypt decrypts encryptedMessage string into decrypted raw string
func (g *GooglePayTokenRecipient) Decrypt(resp GooglePayTokenResponse, recipientKeyIndex int) (*string, error) {
	signedMessage := SignedMessage{}
	err := json.Unmarshal([]byte(resp.SignedMessageStr), &signedMessage)
	if err != nil {
		return nil, err
	}
	merchantPrivateKey, err := ParsePrivateKey(g.RecipientPrivateKeys[recipientKeyIndex])
	if err != nil {
		return nil, err
	}
	ellipticPrivateKey := subtle.ImportECDSA(merchantPrivateKey)
	eciesHkdf := hybrid.EciesHkdfRecipientKem{*ellipticPrivateKey}
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

//Unseal iterates through all publicKeys and merchantPrivateKeys,
//	marshalls data into DecryptedMessage struct, then checks expiration
func (g *GooglePayTokenRecipient) Unseal(resp GooglePayTokenResponse) (*DecryptedMessage, error) {

	//Cycle through all public keys
	var err error
	for i := 0; i < len(g.KeyMananger.CurrentKeys.Keys); i++ {
		err := g.Verify(resp, i)
		if err == nil {
			break
		}
	}
	if err != nil {
		return nil, err
	}

	//iterate all privatekeys to find the one which works
	var decryptedMessage *string
	for i := 0; i < len(g.RecipientPrivateKeys); i++ {
		decryptedMessage, err = g.Decrypt(resp, i)
		if err == nil {
			break
		}
	}
	if err != nil {
		return nil, err
	}

	decryptedMessageStruct := DecryptedMessage{}
	err = json.Unmarshal([]byte(*decryptedMessage), &decryptedMessageStruct)
	if err != nil {
		return nil, err
	}

	err = validateExpirationDate(decryptedMessageStruct)
	if err != nil {
		return nil, err
	}

	return &decryptedMessageStruct, nil
}

func validateExpirationDate(mess DecryptedMessage) error {
	expiration, err := strconv.ParseInt(mess.MessageExpiration, 0, 0)
	if err != nil {
		return err
	}
	if expiration < time.Now().Unix() {
		return errors.New("Message is expired!")
	}
	return nil
}

// Verify authenticates message using ECDSA and specific public key
func (g *GooglePayTokenRecipient) Verify(resp GooglePayTokenResponse, publicKeyIndex int) error {
	toVerify := g.generateToVerify(resp)

	signatureBytes, err := base64.StdEncoding.DecodeString(resp.Signature)
	if err != nil {
		return err
	}

	x, y, err := DecodePublicKey(g.KeyMananger.CurrentKeys.Keys[publicKeyIndex].KeyValue)

	ecdsaPublicKey := ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}

	verifier, err := signature.NewEcdsaVerifyFromPublicKey("SHA256", "DER", &ecdsaPublicKey)
	if err != nil {
		return err
	}

	err = verifier.Verify(signatureBytes, toVerify)
	if err != nil {
		return err
	}
	return nil
}
