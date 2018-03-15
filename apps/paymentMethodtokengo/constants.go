package paymentmethodtokengo

//GooglePayConstants stores the same constants as from Java code
type GooglePayConstants struct {
	GOOGLE_SENDER_ID              string
	HMAC_SHA256_ALGO              string
	HKDF_EMPTY_SALT               []byte
	GOOGLE_CONTEXT_INFO_ECV1      []byte
	AES_CTR_ALGO                  string
	AES_CTR_KEY_SIZE              int
	AES_CTR_ALGO_IV               []byte
	HMAC_SHA256_KEY_SIZE          int
	EllipticCurveType             string
	ElliptictCurvePointFormatType string
	PROTOCOL_VERSION_EC_V1        string
	ECDSA_SHA256_SIGNING_ALGO     string
	JSON_ENCRYPTED_MESSAGE_KEY    string
	JSON_TAG_KEY                  string
	JSON_EPHEMERAL_PUBLIC_KEY     string
	JSON_SIGNATURE_KEY            string
	JSON_SIGNED_MESSAGE_KEY       string
	JSON_PROTOCOL_VERSION_KEY     string
	JSON_MESSAGE_EXPIRATION_KEY   string
}

/*
Instead of global variables, we just set a map with dependencies
*/
func getConstants() GooglePayConstants {

	return GooglePayConstants{"Google", "SHA256", make([]byte, 0),
		[]byte("Google"), "AES/CTR/NoPadding", 16,
		make([]byte, 16), 16, "NIST_P256", "UNCOMPRESSED",
		"ECv1", "SHA256WithECDSA", "encryptedMessage", "tag",
		"ephemeralPublicKey", "signature", "signedMessage", "protocolVersion", "messageExpiration"}

}
