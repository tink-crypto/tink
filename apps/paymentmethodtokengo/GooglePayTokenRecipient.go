package paymentmethodtokengo

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"log"

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

func (g *GooglePayTokenRecipient) Unseal(resp GooglePayTokenResponse) (*DecryptedMessage, error) {
	err := g.Verify(resp)
	if err != nil {
		return nil, err
	}
	signedMessage := SignedMessage{}
	err = json.Unmarshal([]byte(resp.SignedMessageStr), &signedMessage)
	if err != nil {
		return nil, err
	}

	pk, err := base64.StdEncoding.DecodeString(signedMessage.EphemeralPublicKey)
	if err != nil {
		return nil, err
	}

	googlePayConstants := getConstants()
	symmetricKeySize := googlePayConstants.AES_CTR_KEY_SIZE + googlePayConstants.HMAC_SHA256_KEY_SIZE

	log.Println(pk, symmetricKeySize)
	// merchantPrivateKey := ecdsa.PrivateKey{, D}

	// eciesHkdf := subtle.EciesHkdfRecipientKem{ecdsa.PrivateKey}
	// byte[] demKey =
	// 		recipientKem.generateKey(
	// 				kem,
	// 				PaymentMethodTokenConstants.HMAC_SHA256_ALGO,
	// 				PaymentMethodTokenConstants.HKDF_EMPTY_SALT,
	// 				contextInfo,
	// 				symmetricKeySize,
	// 				PaymentMethodTokenConstants.UNCOMPRESSED_POINT_FORMAT);
	// byte[] hmacSha256Key =
	// 		Arrays.copyOfRange(
	// 				demKey, PaymentMethodTokenConstants.AES_CTR_KEY_SIZE, symmetricKeySize);
	// byte[] encryptedMessage =
	// 		Base64.decode(json.getString(PaymentMethodTokenConstants.JSON_ENCRYPTED_MESSAGE_KEY));
	// byte[] computedTag = PaymentMethodTokenUtil.hmacSha256(hmacSha256Key, encryptedMessage);
	// byte[] expectedTag = Base64.decode(json.getString(PaymentMethodTokenConstants.JSON_TAG_KEY));
	// if (!Bytes.equal(expectedTag, computedTag)) {
	// 	throw new GeneralSecurityException("cannot decrypt; invalid MAC");
	// }
	// byte[] aesCtrKey =
	// 		Arrays.copyOfRange(demKey, 0, PaymentMethodTokenConstants.AES_CTR_KEY_SIZE);

	return nil, nil
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

	googlePublicKey := Asn1GooglePublicKey{}
	x, y, err := googlePublicKey.DecodePublicKey(g.KeyMananger.CurrentKeys.Keys[0].KeyValue)

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
