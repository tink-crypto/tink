package paymentmethodtokengo

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

	return GooglePayConstants{"Google", "HmacSha256", make([]byte, 0),
		[]byte("Google"), "AES/CTR/NoPadding", 16,
		make([]byte, 16), 16, "NIST_P256", "UNCOMPRESSED",
		"ECv1", "SHA256WithECDSA", "encryptedMessage", "tag",
		"ephemeralPublicKey", "signature", "signedMessage", "protocolVersion", "messageExpiration"}

}

// public static final String GOOGLE_SENDER_ID = "Google";
// public static final String HMAC_SHA256_ALGO = "HmacSha256";
// public static final byte[] HKDF_EMPTY_SALT = new byte[0];
// public static final byte[] GOOGLE_CONTEXT_INFO_ECV1 = "Google".getBytes(StandardCharsets.UTF_8);
// public static final String AES_CTR_ALGO = "AES/CTR/NoPadding";
// public static final int AES_CTR_KEY_SIZE = 16;
// // Zero IV is fine here because each encryption uses a unique key.
// public static final byte[] AES_CTR_ZERO_IV = new byte[16];
// public static final int HMAC_SHA256_KEY_SIZE = 16;
// public static final EllipticCurves.CurveType P256_CURVE_TYPE =
//     EllipticCurves.CurveType.NIST_P256;
// public static final EllipticCurves.PointFormatType UNCOMPRESSED_POINT_FORMAT =
//     EllipticCurves.PointFormatType.UNCOMPRESSED;
// public static final String PROTOCOL_VERSION_EC_V1 = "ECv1";
// public static final String ECDSA_SHA256_SIGNING_ALGO = "SHA256WithECDSA";
//
// public static final String JSON_ENCRYPTED_MESSAGE_KEY = "encryptedMessage";
// public static final String JSON_TAG_KEY = "tag";
// public static final String JSON_EPHEMERAL_PUBLIC_KEY = "ephemeralPublicKey";
// public static final String JSON_SIGNATURE_KEY = "signature";
// public static final String JSON_SIGNED_MESSAGE_KEY = "signedMessage";
// public static final String JSON_PROTOCOL_VERSION_KEY = "protocolVersion";
// public static final String JSON_MESSAGE_EXPIRATION_KEY = "messageExpiration";
