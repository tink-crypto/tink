// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

package com.google.crypto.tink.apps.paymentmethodtoken;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertEquals;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for the exact Json-Encoding produced. */
@RunWith(JUnit4.class)
public final class PaymentMethodJsonEncodingTest {

  @Test
  public void testExactOutputOfJsonEncodeCiphertext() throws Exception {
    byte[] ciphertext = "CiPhErTeXt".getBytes(UTF_8);
    byte[] tag = "taaag".getBytes(UTF_8);
    byte[] ephemeralPublicKey = "ephemeral Public Key".getBytes(UTF_8);

    String jsonEncodedCiphertext =
        PaymentMethodTokenHybridEncrypt.jsonEncodeCiphertext(ciphertext, tag, ephemeralPublicKey);

    // JSONObject uses a HashMap, where the ordering is not defined. The ordering is however
    // deterministic. And for jsonEncodeCiphertext, the order happens to be first "encryptedMessage"
    // then "ephemeralPublicKey", and finally "tag". Also, JSONObject uses HTML-safe encoding.
    assertEquals(
        "{\"encryptedMessage\":\"Q2lQaEVyVGVYdA\\u003d\\u003d\",\"ephemeralPublicKey\":"
            + "\"ZXBoZW1lcmFsIFB1YmxpYyBLZXk\\u003d\",\"tag\":\"dGFhYWc\\u003d\"}",
        jsonEncodedCiphertext);
  }

  @Test
  public void testExactOutputOfJsonEncodeSignedMessage() throws Exception {
    String senderIntermediateCert =
        "{\"signedKey\":\"{\\\"keyValue\\\":\\\"abcde\\\\u003d\\\\u003d\\\",\\\"keyExpiration\\\""
            + ":\\\"1615299372858\\\"}\",\"signatures\":[\"fghijkl\\u003d\"]}";
    String version = "ECv1";
    String message =
        "{\"encryptedMessage\":\"Q2lQaEVyVGVYdA\\u003d\\u003d\",\"ephemeralPublicKey\":\"ZXBoZW1l"
            + "cmFsIFB1YmxpYyBLZXk\\u003d\",\"tag\":\"dGFhYWc\\u003d\"}";
    byte[] signature = "the signature".getBytes(UTF_8);

    String jsonEncodedSignedMessage =
        PaymentMethodTokenSender.jsonEncodeSignedMessage(
            message, version, signature, senderIntermediateCert);

    String expected =
        "{\"signature\":\"dGhlIHNpZ25hdHVyZQ\\u003d\\u003d\",\"intermediateSigningKey\":{\"signe"
            + "dKey\":\"{\\\"keyValue\\\":\\\"abcde\\\\u003d\\\\u003d\\\",\\\"keyExpiration\\\":"
            + "\\\"1615299372858\\\"}\",\"signatures\":[\"fghijkl\\u003d\"]},\"protocolVersion\""
            + ":\"ECv1\",\"signedMessage\":\"{\\\"encryptedMessage\\\":\\\"Q2lQaEVyVGVYdA\\\\u00"
            + "3d\\\\u003d\\\",\\\"ephemeralPublicKey\\\":\\\"ZXBoZW1lcmFsIFB1YmxpYyBLZXk\\\\u00"
            + "3d\\\",\\\"tag\\\":\\\"dGFhYWc\\\\u003d\\\"}\"}";
    assertEquals(expected, jsonEncodedSignedMessage);

    String expected2 =
        "{\"signature\":\"dGhlIHNpZ25hdHVyZQ\\u003d\\u003d\",\"protocolVersion\":\"ECv1\",\"sign"
            + "edMessage\":\"{\\\"encryptedMessage\\\":\\\"Q2lQaEVyVGVYdA\\\\u003d\\\\u003d\\\","
            + "\\\"ephemeralPublicKey\\\":\\\"ZXBoZW1lcmFsIFB1YmxpYyBLZXk\\\\u003d\\\",\\\"tag\\"
            + "\":\\\"dGFhYWc\\\\u003d\\\"}\"}";

    String jsonEncodedSignedMessage2 =
        PaymentMethodTokenSender.jsonEncodeSignedMessage(message, version, signature, null);
    assertEquals(expected2, jsonEncodedSignedMessage2);
  }
}
