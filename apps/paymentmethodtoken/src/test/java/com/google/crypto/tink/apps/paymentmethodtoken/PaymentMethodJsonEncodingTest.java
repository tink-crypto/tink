// Copyright 2021 Google LLC
//
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

import java.util.ArrayList;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for the exact Json-Encoding produced.
 *
 * These tests test implementation details. Do not depend on the this. For example, the particular
 * ordering of the elements or the particular character escaping used may change in the future.
 * */
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

  @Test
  public void testExactOutputOfJsonEncodedSignedKey() throws Exception {
    String intermediateSigningKey =
        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE/1+3HBVSbdv+j7NaArdgMyoSA"
            + "M43yRydzqdg1TxodSzA96Dj4Mc1EiKroxxunavVIvdxGnJeFViTzFvzFRxyCw==";
    long expiration = 1520836260646L;
    assertEquals(
        "{\"keyValue\":\"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE/1+3HBVSbdv+j7NaArdgMyoSAM43yRydzqdg1"
            + "TxodSzA96Dj4Mc1EiKroxxunavVIvdxGnJeFViTzFvzFRxyCw\\u003d\\u003d\",\"keyExpiration\""
            + ":\"1520836260646\"}",
        SenderIntermediateCertFactory.jsonEncodeSignedKey(intermediateSigningKey, expiration));
  }

  @Test
  public void testExactOutputOfJsonEncodeCertificate() throws Exception {
    String intermediateSigningKey =
        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE/1+3HBVSbdv+j7NaArdgMyoSA"
            + "M43yRydzqdg1TxodSzA96Dj4Mc1EiKroxxunavVIvdxGnJeFViTzFvzFRxyCw==";
    long expiration = 1520836260646L;
    String signedKey =
        SenderIntermediateCertFactory.jsonEncodeSignedKey(intermediateSigningKey, expiration);
    ArrayList<String> signatures = new ArrayList<>();
    signatures.add("iTzFvzFRxyCw==");
    signatures.add("abcde090/+==");
    signatures.add("xyz");
    String expected =
        "{\"signedKey\":\"{\\\"keyValue\\\":\\\"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE"
            + "/1+3HBVSbdv+j7NaArdgMyoSAM43yRydzqdg1TxodSzA96Dj4Mc1EiKroxxunavVIvdxGnJeFViTzFvzFRx"
            + "yCw\\\\u003d\\\\u003d\\\",\\\"keyExpiration\\\":\\\"1520836260646\\\"}\",\"signatur"
            + "es\":[\"iTzFvzFRxyCw\\u003d\\u003d\",\"abcde090/+\\u003d\\u003d\",\"xyz\"]}";
    assertEquals(
        expected, SenderIntermediateCertFactory.jsonEncodeCertificate(signedKey, signatures));
  }

  @Test
  public void testExactOutputOfWeirdJsonEncodeCertificate() throws Exception {
    String intermediateSigningKey =
        "\"\\==";
    long expiration = -123;
    String signedKey =
        SenderIntermediateCertFactory.jsonEncodeSignedKey(intermediateSigningKey, expiration);
    ArrayList<String> signatures = new ArrayList<>();
    signatures.add("");
    signatures.add("\\\"/+==");
    String expected =
        "{\"signedKey\":\"{\\\"keyValue\\\":\\\"\\\\\\\"\\\\\\\\\\\\u003d\\\\u003d"
            + "\\\",\\\"keyExpiration\\\":\\\"-123\\\"}\",\"signatures\":[\"\",\"\\\\\\\"/+\\u003d"
            + "\\u003d\"]}";
    assertEquals(
        expected, SenderIntermediateCertFactory.jsonEncodeCertificate(signedKey, signatures));
  }
}
