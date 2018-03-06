package paymentmethodtokengo

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"log"
	"math/big"

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

	asn1Key := Asn1GooglePublicKey{}
	bytesToUnmarshal, err := base64.StdEncoding.DecodeString(g.KeyMananger.CurrentKeys.Keys[0].KeyValue)
	if err != nil {
		return err
	}
	_, err = asn1.Unmarshal(bytesToUnmarshal, &asn1Key) //TODO:this is ugly
	if err != nil {
		log.Println(g.KeyMananger.CurrentKeys.Keys[0].KeyValue)
		return err
	}

	x := new(big.Int)
	x.SetBytes(asn1Key.Bits.Bytes[1:33])
	y := new(big.Int)
	y.SetBytes(asn1Key.Bits.Bytes[34:65])

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
