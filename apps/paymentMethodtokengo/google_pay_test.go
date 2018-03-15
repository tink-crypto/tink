package paymentmethodtokengo

//These tests are stolen from java app

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

var MERCHANT_PUBLIC_KEY_BASE64 = "BOdoXP+9Aq473SnGwg3JU1aiNpsd9vH2ognq4PtDtlLGa3Kj8TPf+jaQNPyDSkh3JUhiS0KyrrlWhAgNZKHYF2Y="

/**
 * Sample merchant private key.
 *
 * <p>Corresponds to the private key of {@link #MERCHANT_PUBLIC_KEY_BASE64}
 *
 * <pre>
 * openssl pkcs8 -topk8 -inform PEM -outform PEM -in merchant-key.pem -nocrypt
 * </pre>
 */
var MERCHANT_PRIVATE_KEY_PKCS8_BASE64 = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgCPSuFr4iSIaQprjj" +
	"chHPyDu2NXFe0vDBoTpPkYaK9dehRANCAATnaFz/vQKuO90pxsINyVNWojabHfbx" +
	"9qIJ6uD7Q7ZSxmtyo/Ez3/o2kDT8g0pIdyVIYktCsq65VoQIDWSh2Bdm"

/** An alternative merchant private key used during the tests. */
var ALTERNATE_MERCHANT_PRIVATE_KEY_PKCS8_BASE64 = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgOUIzccyJ3rTx6SVm" +
	"XrWdtwUP0NU26nvc8KIYw2GmYZKhRANCAAR5AjmTNAE93hQEQE+PryLlgr6Q7FXyN" +
	"XoZRk+1Fikhq61mFhQ9s14MOwGBxd5O6Jwn/sdUrWxkYk3idtNEN1Rz"

/** Sample Google provided JSON with its public signing keys. */
var GOOGLE_VERIFYING_PUBLIC_KEYS_JSON = "{\n" +
	"  \"keys\": [\n" +
	"    {\n" +
	"      \"keyValue\": \"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEPYnHwS8uegWAewQtlxizmLFynw" +
	"HcxRT1PK07cDA6/C4sXrVI1SzZCUx8U8S0LjMrT6ird/VW7be3Mz6t/srtRQ==\",\n" +
	"      \"protocolVersion\": \"ECv1\"\n" +
	"    }\n" +
	"  ]\n" +
	"}"

/**
 * Sample Google private signing key.
 *
 * <p>Corresponds to private key of the key in {@link #GOOGLE_VERIFYING_PUBLIC_KEYS_JSON}.
 */
var GOOGLE_SIGNING_PRIVATE_KEY_PKCS8_BASE64 = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgZj/Dldxz8fvKVF5O" +
	"TeAtK6tY3G1McmvhMppe6ayW6GahRANCAAQ9icfBLy56BYB7BC2XGLOYsXKfAdzF" +
	"FPU8rTtwMDr8LixetUjVLNkJTHxTxLQuMytPqKt39Vbtt7czPq3+yu1F"

var RECIPIENT_ID = "someRecipient"

var PLAINTEXT = "plaintext"

/**
 * The result of {@link #PLAINTEXT} encrypted with {@link #MERCHANT_PRIVATE_KEY_PKCS8_BASE64} and
 * signed with the only key in {@link #GOOGLE_VERIFYING_PUBLIC_KEYS_JSON}.
 */
var CIPHERTEXT = "{" + "\"protocolVersion\":\"ECv1\"," +
	"\"signedMessage\":" +
	("\"{" +
		"\\\"tag\\\":\\\"ZVwlJt7dU8Plk0+r8rPF8DmPTvDiOA1UAoNjDV+SqDE\\\\u003d\\\"," +
		"\\\"ephemeralPublicKey\\\":\\\"BPhVspn70Zj2Kkgu9t8+ApEuUWsI/zos5whGCQBlgOkuYagOis7" +
		"qsrcbQrcprjvTZO3XOU+Qbcc28FSgsRtcgQE\\\\u003d\\\"," +
		"\\\"encryptedMessage\\\":\\\"12jUObueVTdy\\\"}\",") +
	"\"signature\":\"MEQCIDxBoUCoFRGReLdZ/cABlSSRIKoOEFoU3e27c14vMZtfAiBtX3pGMEpnw6mSAbnagC" +
	"CgHlCk3NcFwWYEyxIE6KGZVA\\u003d\\u003d\"}"

var ALTERNATE_PUBLIC_SIGNING_KEY = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEU8E6JppGKFG40r5dDU1idHRN52NuwsemFzXZh1oUqh3bGUPgPioH+RoW" +
	"nmVSUQz1WfM2426w9f0GADuXzpUkcw=="

func TestVerifyWorksWithKey(t *testing.T) {
	var trustedKeysJson KeysResponse
	err := json.Unmarshal([]byte(GOOGLE_VERIFYING_PUBLIC_KEYS_JSON), &trustedKeysJson)
	assert.NoError(t, err)

	keyManager := GooglePaymentsPublicKeyManager{}
	keyManager.CurrentKeys = trustedKeysJson
	keyManager.KeysUrl = KEYS_URL_TEST

	recipient := GooglePayTokenRecipient{}
	recipient.KeyMananger = keyManager
	recipient.RecipientID = RECIPIENT_ID
	recipient.RecipientPrivateKeys = []string{MERCHANT_PRIVATE_KEY_PKCS8_BASE64}

	payToken := GooglePayTokenResponse{}
	err = json.Unmarshal([]byte(CIPHERTEXT), &payToken)
	assert.NoError(t, err)

	err = recipient.Verify(payToken, 0)
	assert.NoError(t, err)

}

func TestDecryptWorksWithKey(t *testing.T) {
	var trustedKeysJson KeysResponse
	err := json.Unmarshal([]byte(GOOGLE_VERIFYING_PUBLIC_KEYS_JSON), &trustedKeysJson)
	assert.NoError(t, err)

	keyManager := GooglePaymentsPublicKeyManager{}
	keyManager.CurrentKeys = trustedKeysJson
	keyManager.KeysUrl = KEYS_URL_TEST

	recipient := GooglePayTokenRecipient{}
	recipient.KeyMananger = keyManager
	recipient.RecipientID = RECIPIENT_ID
	recipient.RecipientPrivateKeys = []string{MERCHANT_PRIVATE_KEY_PKCS8_BASE64}

	payToken := GooglePayTokenResponse{}
	err = json.Unmarshal([]byte(CIPHERTEXT), &payToken)
	assert.NoError(t, err)

	decrypted, err := recipient.Decrypt(payToken, 0)
	assert.NotNil(t, decrypted)
	assert.NoError(t, err)
	// assert.Equal(t, *decrypted, PLAINTEXT)

}
