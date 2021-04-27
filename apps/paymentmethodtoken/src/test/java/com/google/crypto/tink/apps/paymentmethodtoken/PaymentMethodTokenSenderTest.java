// Copyright 2017 Google Inc.
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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import com.google.crypto.tink.subtle.EllipticCurves;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import org.joda.time.Duration;
import org.joda.time.Instant;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for {@code PaymentMethodTokenSender}. */
@RunWith(JUnit4.class)
public class PaymentMethodTokenSenderTest {
  private static final String MERCHANT_PUBLIC_KEY_BASE64 =
      "BOdoXP+9Aq473SnGwg3JU1aiNpsd9vH2ognq4PtDtlLGa3Kj8TPf+jaQNPyDSkh3JUhiS0KyrrlWhAgNZKHYF2Y=";
  /**
   * Created with:
   *
   * <pre>
   * openssl pkcs8 -topk8 -inform PEM -outform PEM -in merchant-key.pem -nocrypt
   * </pre>
   */
  private static final String MERCHANT_PRIVATE_KEY_PKCS8_BASE64 =
      "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgCPSuFr4iSIaQprjj"
          + "chHPyDu2NXFe0vDBoTpPkYaK9dehRANCAATnaFz/vQKuO90pxsINyVNWojabHfbx"
          + "9qIJ6uD7Q7ZSxmtyo/Ez3/o2kDT8g0pIdyVIYktCsq65VoQIDWSh2Bdm";

  /** Sample Google provided JSON with its public signing keys. */
  private static final String GOOGLE_VERIFYING_PUBLIC_KEYS_JSON =
      "{\n"
          + "  \"keys\": [\n"
          + "    {\n"
          + "      \"keyValue\": \"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEPYnHwS8uegWAewQtlxizmLFynw"
          + "HcxRT1PK07cDA6/C4sXrVI1SzZCUx8U8S0LjMrT6ird/VW7be3Mz6t/srtRQ==\",\n"
          + "      \"protocolVersion\": \"ECv1\"\n"
          + "    },\n"
          + "    {\n"
          + "      \"keyValue\": \"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE/1+3HBVSbdv+j7NaArdgMyoSAM"
          + "43yRydzqdg1TxodSzA96Dj4Mc1EiKroxxunavVIvdxGnJeFViTzFvzFRxyCw==\",\n"
          + "      \"keyExpiration\": \""
          + Instant.now().plus(Duration.standardDays(1)).getMillis()
          + "\",\n"
          + "      \"protocolVersion\": \"ECv2\"\n"
          + "    },\n"
          + "    {\n"
          + "      \"keyValue\": \"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAENXvYqxD5WayKYhuXQevdGdLA8i"
          + "fV4LsRS2uKvFo8wwyiwgQHB9DiKzG6T/P1Fu9Bl7zWy/se5Dy4wk1mJoPuxg==\",\n"
          + "      \"keyExpiration\": \""
          + Instant.now().plus(Duration.standardDays(1)).getMillis()
          + "\",\n"
          + "      \"protocolVersion\": \"ECv2SigningOnly\"\n"
          + "    }\n"
          + "  ]\n"
          + "}";

  /**
   * Sample Google private signing key for the ECv1 protocolVersion.
   *
   * <p>Corresponds to the ECv1 private key of the key in {@link
   * #GOOGLE_VERIFYING_PUBLIC_KEYS_JSON}.
   */
  private static final String GOOGLE_SIGNING_EC_V1_PRIVATE_KEY_PKCS8_BASE64 =
      "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgZj/Dldxz8fvKVF5O"
          + "TeAtK6tY3G1McmvhMppe6ayW6GahRANCAAQ9icfBLy56BYB7BC2XGLOYsXKfAdzF"
          + "FPU8rTtwMDr8LixetUjVLNkJTHxTxLQuMytPqKt39Vbtt7czPq3+yu1F";

  /**
   * Sample Google private signing key for the ECv2 protocolVersion.
   *
   * <p>Corresponds to ECv2 private key of the key in {@link #GOOGLE_VERIFYING_PUBLIC_KEYS_JSON}.
   */
  private static final String GOOGLE_SIGNING_EC_V2_PRIVATE_KEY_PKCS8_BASE64 =
      "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgKvEdSS8f0mjTCNKev"
          + "aKXIzfNC5b4A104gJWI9TsLIMqhRANCAAT/X7ccFVJt2/6Ps1oCt2AzKhIAz"
          + "jfJHJ3Op2DVPGh1LMD3oOPgxzUSIqujHG6dq9Ui93Eacl4VWJPMW/MVHHIL";

  /**
   * Sample Google intermediate public signing key for the ECv2 protocolVersion.
   *
   * <p>Base64 version of the public key encoded in ASN.1 type SubjectPublicKeyInfo defined in the
   * X.509 standard.
   *
   * <p>The intermediate public key will be signed by {@link
   * #GOOGLE_SIGNING_EC_V2_PRIVATE_KEY_PKCS8_BASE64}.
   */
  private static final String GOOGLE_SIGNING_EC_V2_INTERMEDIATE_PUBLIC_KEY_X509_BASE64 =
      "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE/1+3HBVSbdv+j7NaArdgMyoSAM43yR"
          + "ydzqdg1TxodSzA96Dj4Mc1EiKroxxunavVIvdxGnJeFViTzFvzFRxyCw==";

  /**
   * Sample Google intermediate private signing key for the ECv2 protocolVersion.
   *
   * <p>Corresponds to private key of the key in {@link
   * #GOOGLE_SIGNING_EC_V2_INTERMEDIATE_PUBLIC_KEY_X509_BASE64}.
   */
  private static final String GOOGLE_SIGNING_EC_V2_INTERMEDIATE_PRIVATE_KEY_PKCS8_BASE64 =
      "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgKvEdSS8f0mjTCNKev"
          + "aKXIzfNC5b4A104gJWI9TsLIMqhRANCAAT/X7ccFVJt2/6Ps1oCt2AzKhIAz"
          + "jfJHJ3Op2DVPGh1LMD3oOPgxzUSIqujHG6dq9Ui93Eacl4VWJPMW/MVHHIL";

  /**
   * Sample Google private signing key for the ECV2SigningOnly protocolVersion.
   *
   * <p>Corresponds to ECV2SigningOnly private key of the key in {@link
   * #GOOGLE_VERIFYING_PUBLIC_KEYS_JSON}.
   */
  private static final String GOOGLE_SIGNING_EC_V2_SIGNING_ONLY_PRIVATE_KEY_PKCS8_BASE64 =
      "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgRi9hSdY+knJ08odnY"
          + "tZFMRi7ZYeMoasAijLhD4GiQ1yhRANCAAQ1e9irEPlZrIpiG5dB690Z0sDy"
          + "J9XguxFLa4q8WjzDDKLCBAcH0OIrMbpP8/UW70GXvNbL+x7kPLjCTWYmg+7G";

  /**
   * Sample Google intermediate public signing key for the ECV2SigningOnly protocolVersion.
   *
   * <p>Base64 version of the public key encoded in ASN.1 type SubjectPublicKeyInfo defined in the
   * X.509 standard.
   *
   * <p>The intermediate public key will be signed by {@link
   * #GOOGLE_SIGNING_EC_V2_SIGNING_ONLY_PRIVATE_KEY_PKCS8_BASE64}.
   */
  private static final String
      GOOGLE_SIGNING_EC_V2_SIGNING_ONLY_INTERMEDIATE_PUBLIC_KEY_X509_BASE64 =
          "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE8OaurwvbyYm8JWDgFPRTIDg0/"
              + "kcQTFAQ4txi5IP0AyM1QiagwRhDUfjpqZkpw8xt/DXwyWYM0DdHqoeV"
              + "TKqmYQ==";

  /**
   * Sample Google intermediate private signing key for the ECV2SigningOnly protocolVersion.
   *
   * <p>Corresponds to private key of the key in {@link
   * #GOOGLE_SIGNING_EC_V2_SIGNING_ONLY_INTERMEDIATE_PUBLIC_KEY_X509_BASE64}.
   */
  private static final String
      GOOGLE_SIGNING_EC_V2_SIGNING_ONLY_INTERMEDIATE_PRIVATE_KEY_PKCS8_BASE64 =
          "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg+Jvpkq26tpZ0s"
              + "TTZVh4teEI41SnJdmkBzM8VZ5ZirE2hRANCAATw5q6vC9vJibwlYOAU"
              + "9FMgODT+RxBMUBDi3GLkg/QDIzVCJqDBGENR+OmpmSnDzG38NfDJZgz"
              + "QN0eqh5VMqqZh";

  private static final String RECIPIENT_ID = "someRecipient";

  @Test
  public void testECV1WithPrecomputedKeys() throws Exception {
    PaymentMethodTokenSender sender =
        new PaymentMethodTokenSender.Builder()
            .senderSigningKey(GOOGLE_SIGNING_EC_V1_PRIVATE_KEY_PKCS8_BASE64)
            .recipientId(RECIPIENT_ID)
            .rawUncompressedRecipientPublicKey(MERCHANT_PUBLIC_KEY_BASE64)
            .build();

    PaymentMethodTokenRecipient recipient =
        new PaymentMethodTokenRecipient.Builder()
            .senderVerifyingKeys(GOOGLE_VERIFYING_PUBLIC_KEYS_JSON)
            .recipientId(RECIPIENT_ID)
            .addRecipientPrivateKey(MERCHANT_PRIVATE_KEY_PKCS8_BASE64)
            .build();

    String plaintext = "blah";
    assertEquals(plaintext, recipient.unseal(sender.seal(plaintext)));
  }

  @Test
  public void testECV1WithTestdataSeal() throws Exception {
    PaymentMethodTokenRecipient recipient =
        new PaymentMethodTokenRecipient.Builder()
            .senderVerifyingKeys(GOOGLE_VERIFYING_PUBLIC_KEYS_JSON)
            .recipientId(RECIPIENT_ID)
            .addRecipientPrivateKey(MERCHANT_PRIVATE_KEY_PKCS8_BASE64)
            .build();

    // Seal where "=" has been escaped by \u003d.
    // - tag is "bkd9lJMV/8Na34/9ZtZmDmgrZcxJ71ALhT/KpraqzR8=", = gets escapced by \u003d, so
    //   signedMessage contains "tag": "bkd9lJMV/8Na34/9ZtZmDmgrZcxJ71ALhT/KpraqzR8\u003d"
    // - this gets escaped in the 2nd encoding with \ -> \\ and " -> \". So the final seal
    //   contains \"tag\":\"bkd9lJMV/8Na34/9ZtZmDmgrZcxJ71ALhT/KpraqzR8\\u003d\"
    // Note that to encode this string in Java, we have to escape \ -> \\ and " -> \" again.
    String testdataSeal =
        "{\"signedMessage\":\"{\\\"tag\\\":\\\"bkd9lJMV/8Na34/9ZtZmDmgrZcxJ71ALhT/KpraqzR8\\\\u003d"
            + "\\\",\\\"ephemeralPublicKey\\\":\\\"BLyk1Iwcx+yRQbCSsZgAwb8s/ChNDTlcCovgL5/37qDdia3x"
            + "PM5GUb+HmbW9bF/c12p0ySxtU/MDcNkJZ0nWCVs\\\\u003d\\\",\\\"encryptedMessage\\\":\\\"ue"
            + "63Gg\\\\u003d\\\\u003d\\\"}\",\"protocolVersion\":\"ECv1\",\"signature\":\"MEQCIFFdW"
            + "ve35+jh7CT9QC9W6Leqx32P41oNxG2NDm6PaY1fAiAKHvklWHDPiLKYPb0zyXRGIl6GYvfQ3LAl1z5sR3CbS"
            + "w\\u003d\\u003d\"}";

    // Seal where "=" has not been escaped, but " and \ have to be escaped as before.
    String testdataSeal2 =
        "{\"signedMessage\":\"{\\\"encryptedMessage\\\":\\\"Ih3e7g==\\\",\\\"tag\\\":\\\"GlZ332kL5u"
            + "ZICWrCsSSQ6KrFFqQyKI84SH2Wh6UTv8c=\\\",\\\"ephemeralPublicKey\\\":\\\"BBb/VaSEYJphhs"
            + "ma1X24QrjdFr/DHo7IDu8owi6NR0tW9p5F9jn6wxu5by5Rs/bYkVdr8HNT9+MEpBOnL7Si/dQ=\\\"}\",\""
            + "protocolVersion\":\"ECv1\",\"signature\":\"MEYCIQD6rOV4l9pm/MDr2jPkqnU2GSHbbnUaLYQow"
            + "/0Y+S1axAIhAKUUO7N9eoBNuXySDDWDYrdu7r0IHxeeFtkubDxhplYU\"}";

    // Seal where "=" has only been escaped in the outer encoding:
    // - tag is "Jv2KH2lCVyNgGcQMbWSMf+N8RQCgTfkRq3J3f9qrBKE=", so
    //   signedMessage contains "tag": "Jv2KH2lCVyNgGcQMbWSMf+N8RQCgTfkRq3J3f9qrBKE="
    // - this gets escaped in the 2nd encoding with \ -> \\, " -> \" and = -> \u003d. So the final
    //   seal contains \"tag\":\"Jv2KH2lCVyNgGcQMbWSMf+N8RQCgTfkRq3J3f9qrBKE\u003d\"
    // Note that to encode this string in Java, we have to escape \ -> \\ and " -> \" again.
    String testdataSeal3 =
        "{\"signedMessage\":\"{\\\"encryptedMessage\\\":\\\"eTBsng\\u003d\\u003d\\\",\\\"tag\\\":\\"
            + "\"Jv2KH2lCVyNgGcQMbWSMf+N8RQCgTfkRq3J3f9qrBKE\\u003d\\\",\\\"ephemeralPublicKey\\\":"
            + "\\\"BGPS6h2ddaOA+H71e28xZ2OQZBJuVrCK3qUXc6G6ykHTr8ab9pmS7B87n9jg8qwYAWpFcRNgC2fxnrPL"
            + "+p2Gk5U\\u003d\\\"}\",\"protocolVersion\":\"ECv1\",\"signature\":\"MEUCIQC+8NTo1xbem"
            + "5lPhXuEwcYc0W03jdj3Q1YNI4XvoVAbuAIgT5WXy1wZ2GNXoaLauNGo0iHeOjsZT3wYUziZPHkSAlk\\u003"
            + "d\"}";

    // Weird token where for no reason the characters { -> \u007b and s -> \u0073 have been escaped.
    String testdataSeal4 =
        "{\"\\u0073ignedMe\\u0073\\u0073age\":\"\\u007b\\\"encryptedMe\\\\u0073\\\\u0073age\\\":\\"
            + "\"tfAPcA\\\\u003d\\\\u003d\\\",\\\"tag\\\":\\\"bB72KLdziA4Oca77w7g7a4fbKpgFXVrtUr56W"
            + "NpIL6M\\\\u003d\\\",\\\"ephemeralPublicKey\\\":\\\"BKYBrgWkOP7gqCcIqRjT1t0HjMdbEIMeP"
            + "82VtfC7IaCNbHgL9vojnQ/Yxy8Kutn+MCvG3gRdTxGN+Pwl+1QjM6w\\\\u003d\\\"}\",\"protocolVer"
            + "\\u0073ion\":\"ECv1\",\"\\u0073ignature\":\"MEUCIHDW7JS51iy1LeyiNri7tNqe0HYdPwmDoi/M"
            + "j2RD+3f1AiEA9FBSpqDhQzEvn849IrxXWQlIkuJdUfLE1NxCBQ8mCj0\\u003d\"}";

    String plaintext = "blah";
    assertEquals(plaintext, recipient.unseal(testdataSeal));
    assertEquals(plaintext, recipient.unseal(testdataSeal2));
    assertEquals(plaintext, recipient.unseal(testdataSeal3));
    assertEquals(plaintext, recipient.unseal(testdataSeal4));
  }

  @Test
  public void testECV2WithPrecomputedKeys() throws Exception {
    PaymentMethodTokenSender sender =
        new PaymentMethodTokenSender.Builder()
            .protocolVersion(PaymentMethodTokenConstants.PROTOCOL_VERSION_EC_V2)
            .senderIntermediateSigningKey(
                GOOGLE_SIGNING_EC_V2_INTERMEDIATE_PRIVATE_KEY_PKCS8_BASE64)
            .senderIntermediateCert(
                new SenderIntermediateCertFactory.Builder()
                    .protocolVersion(PaymentMethodTokenConstants.PROTOCOL_VERSION_EC_V2)
                    .addSenderSigningKey(GOOGLE_SIGNING_EC_V2_PRIVATE_KEY_PKCS8_BASE64)
                    .senderIntermediateSigningKey(
                        GOOGLE_SIGNING_EC_V2_INTERMEDIATE_PUBLIC_KEY_X509_BASE64)
                    .expiration(Instant.now().plus(Duration.standardDays(1)).getMillis())
                    .build()
                    .create())
            .recipientId(RECIPIENT_ID)
            .rawUncompressedRecipientPublicKey(MERCHANT_PUBLIC_KEY_BASE64)
            .build();

    PaymentMethodTokenRecipient recipient =
        new PaymentMethodTokenRecipient.Builder()
            .protocolVersion(PaymentMethodTokenConstants.PROTOCOL_VERSION_EC_V2)
            .senderVerifyingKeys(GOOGLE_VERIFYING_PUBLIC_KEYS_JSON)
            .recipientId(RECIPIENT_ID)
            .addRecipientPrivateKey(MERCHANT_PRIVATE_KEY_PKCS8_BASE64)
            .build();

    String plaintext = "blah";
    assertEquals(plaintext, recipient.unseal(sender.seal(plaintext)));
  }

  @Test
  public void testECV2SigningOnlyWithPrecomputedKeys() throws Exception {
    PaymentMethodTokenSender sender =
        new PaymentMethodTokenSender.Builder()
            .protocolVersion(PaymentMethodTokenConstants.PROTOCOL_VERSION_EC_V2_SIGNING_ONLY)
            .senderIntermediateSigningKey(
                GOOGLE_SIGNING_EC_V2_SIGNING_ONLY_INTERMEDIATE_PRIVATE_KEY_PKCS8_BASE64)
            .senderIntermediateCert(
                new SenderIntermediateCertFactory.Builder()
                    .protocolVersion(
                        PaymentMethodTokenConstants.PROTOCOL_VERSION_EC_V2_SIGNING_ONLY)
                    .addSenderSigningKey(GOOGLE_SIGNING_EC_V2_SIGNING_ONLY_PRIVATE_KEY_PKCS8_BASE64)
                    .senderIntermediateSigningKey(
                        GOOGLE_SIGNING_EC_V2_SIGNING_ONLY_INTERMEDIATE_PUBLIC_KEY_X509_BASE64)
                    .expiration(Instant.now().plus(Duration.standardDays(1)).getMillis())
                    .build()
                    .create())
            .recipientId(RECIPIENT_ID)
            .build();

    PaymentMethodTokenRecipient recipient =
        new PaymentMethodTokenRecipient.Builder()
            .protocolVersion(PaymentMethodTokenConstants.PROTOCOL_VERSION_EC_V2_SIGNING_ONLY)
            .senderVerifyingKeys(GOOGLE_VERIFYING_PUBLIC_KEYS_JSON)
            .recipientId(RECIPIENT_ID)
            .build();

    String plaintext = "blah";
    assertEquals(plaintext, recipient.unseal(sender.seal(plaintext)));
  }

  @Test
  public void testShouldThrowWithUnsupportedProtocolVersion() throws Exception {
    try {
      new PaymentMethodTokenSender.Builder().protocolVersion("ECv99").build();
      fail("Should have thrown!");
    } catch (IllegalArgumentException expected) {
      assertEquals("invalid version: ECv99", expected.getMessage());
    }
  }

  @Test
  public void testShouldThrowIfSignedIntermediateSigningKeyIsSetForECV1() throws Exception {
    try {
      new PaymentMethodTokenSender.Builder()
          .protocolVersion(PaymentMethodTokenConstants.PROTOCOL_VERSION_EC_V1)
          .senderSigningKey(GOOGLE_SIGNING_EC_V1_PRIVATE_KEY_PKCS8_BASE64)
          .senderIntermediateCert(newSignedIntermediateSigningKey())
          .build();
      fail("Should have thrown!");
    } catch (IllegalArgumentException expected) {
      assertEquals(
          "must not set signed sender's intermediate signing key using "
              + "Builder.senderIntermediateCert",
          expected.getMessage());
    }
  }

  @Test
  public void testShouldThrowIfIntermediateSigningKeyIsSetForECV1() throws Exception {
    try {
      new PaymentMethodTokenSender.Builder()
          .protocolVersion(PaymentMethodTokenConstants.PROTOCOL_VERSION_EC_V1)
          .senderSigningKey(GOOGLE_SIGNING_EC_V1_PRIVATE_KEY_PKCS8_BASE64)
          .senderIntermediateSigningKey(GOOGLE_SIGNING_EC_V2_INTERMEDIATE_PRIVATE_KEY_PKCS8_BASE64)
          .build();
      fail("Should have thrown!");
    } catch (IllegalArgumentException expected) {
      assertEquals(
          "must not set sender's intermediate signing key using "
              + "Builder.senderIntermediateSigningKey",
          expected.getMessage());
    }
  }

  @Test
  public void testShouldThrowIfSenderSigningKeyIsSetForECV2() throws Exception {
    try {
      new PaymentMethodTokenSender.Builder()
          .protocolVersion(PaymentMethodTokenConstants.PROTOCOL_VERSION_EC_V2)
          .senderSigningKey(GOOGLE_SIGNING_EC_V1_PRIVATE_KEY_PKCS8_BASE64)
          .build();
      fail("Should have thrown!");
    } catch (IllegalArgumentException expected) {
      assertEquals(
          "must not set sender's signing key using Builder.senderSigningKey",
          expected.getMessage());
    }
  }

  @Test
  public void testShouldThrowIfSignedIntermediateSigningKeyIsNotSetForECV2() throws Exception {
    try {
      new PaymentMethodTokenSender.Builder()
          .protocolVersion(PaymentMethodTokenConstants.PROTOCOL_VERSION_EC_V2)
          // no calls to senderIntermediateCert
          .senderIntermediateSigningKey(GOOGLE_SIGNING_EC_V2_INTERMEDIATE_PRIVATE_KEY_PKCS8_BASE64)
          .build();
      fail("Should have thrown!");
    } catch (IllegalArgumentException expected) {
      assertEquals(
          "must set signed sender's intermediate signing key using "
              + "Builder.senderIntermediateCert",
          expected.getMessage());
    }
  }

  @Test
  public void testShouldThrowIfIntermediateSigningKeyIsNotSetForECV2() throws Exception {
    try {
      new PaymentMethodTokenSender.Builder()
          .protocolVersion(PaymentMethodTokenConstants.PROTOCOL_VERSION_EC_V2)
          // no calls to senderIntermediateSigningKey
          .build();
      fail("Should have thrown!");
    } catch (IllegalArgumentException expected) {
      assertEquals(
          "must set sender's intermediate signing key using Builder.senderIntermediateSigningKey",
          expected.getMessage());
    }
  }

  @Test
  public void testShouldThrowIfSenderSigningKeyIsNotSetForECV1() throws Exception {
    try {
      new PaymentMethodTokenSender.Builder()
          .protocolVersion(PaymentMethodTokenConstants.PROTOCOL_VERSION_EC_V1)
          // no calls to senderSigningKey
          .build();
      fail("Should have thrown!");
    } catch (IllegalArgumentException expected) {
      assertEquals(
          "must set sender's signing key using Builder.senderSigningKey", expected.getMessage());
    }
  }

  @Test
  public void testShouldThrowIfSenderSigningKeyIsSetForECV2SigningOnly() throws Exception {
    try {
      new PaymentMethodTokenSender.Builder()
          .protocolVersion(PaymentMethodTokenConstants.PROTOCOL_VERSION_EC_V2_SIGNING_ONLY)
          .senderSigningKey(GOOGLE_SIGNING_EC_V1_PRIVATE_KEY_PKCS8_BASE64)
          .build();
      fail("Should have thrown!");
    } catch (IllegalArgumentException expected) {
      assertEquals(
          "must not set sender's signing key using Builder.senderSigningKey",
          expected.getMessage());
    }
  }

  @Test
  public void testShouldThrowIfSignedIntermediateSigningKeyIsNotSetForECV2SigningOnly()
      throws Exception {
    try {
      new PaymentMethodTokenSender.Builder()
          .protocolVersion(PaymentMethodTokenConstants.PROTOCOL_VERSION_EC_V2_SIGNING_ONLY)
          // no calls to senderIntermediateCert
          .senderIntermediateSigningKey(
              GOOGLE_SIGNING_EC_V2_SIGNING_ONLY_INTERMEDIATE_PRIVATE_KEY_PKCS8_BASE64)
          .build();
      fail("Should have thrown!");
    } catch (IllegalArgumentException expected) {
      assertEquals(
          "must set signed sender's intermediate signing key using "
              + "Builder.senderIntermediateCert",
          expected.getMessage());
    }
  }

  @Test
  public void testShouldThrowIfRecipientPublicKeyIsSetForECV2SigningOnly() throws Exception {
    try {
      new PaymentMethodTokenSender.Builder()
          .protocolVersion(PaymentMethodTokenConstants.PROTOCOL_VERSION_EC_V2_SIGNING_ONLY)
          // no calls to senderIntermediateCert
          .senderIntermediateSigningKey(
              GOOGLE_SIGNING_EC_V2_SIGNING_ONLY_INTERMEDIATE_PRIVATE_KEY_PKCS8_BASE64)
          .rawUncompressedRecipientPublicKey(MERCHANT_PUBLIC_KEY_BASE64)
          .senderIntermediateCert(
              new SenderIntermediateCertFactory.Builder()
                  .protocolVersion(PaymentMethodTokenConstants.PROTOCOL_VERSION_EC_V2_SIGNING_ONLY)
                  .addSenderSigningKey(GOOGLE_SIGNING_EC_V2_SIGNING_ONLY_PRIVATE_KEY_PKCS8_BASE64)
                  .senderIntermediateSigningKey(
                      GOOGLE_SIGNING_EC_V2_SIGNING_ONLY_INTERMEDIATE_PUBLIC_KEY_X509_BASE64)
                  .expiration(Instant.now().plus(Duration.standardDays(1)).getMillis())
                  .build()
                  .create())
          .recipientId(RECIPIENT_ID)
          .build();
      fail("Should have thrown!");
    } catch (IllegalArgumentException expected) {
      assertEquals(
          "must not set recipient's public key using Builder.recipientPublicKey",
          expected.getMessage());
    }
  }

  @Test
  public void testShouldThrowIfIntermediateSigningKeyIsNotSetForECV2SigningOnly() throws Exception {
    try {
      new PaymentMethodTokenSender.Builder()
          .protocolVersion(PaymentMethodTokenConstants.PROTOCOL_VERSION_EC_V2_SIGNING_ONLY)
          // no calls to senderIntermediateSigningKey
          .build();
      fail("Should have thrown!");
    } catch (IllegalArgumentException expected) {
      assertEquals(
          "must set sender's intermediate signing key using Builder.senderIntermediateSigningKey",
          expected.getMessage());
    }
  }

  @Test
  public void testSendReceive() throws Exception {
    ECParameterSpec spec = EllipticCurves.getNistP256Params();
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
    keyGen.initialize(spec);
    String senderId = "foo";
    String recipientId = "bar";

    KeyPair senderKey = keyGen.generateKeyPair();
    ECPublicKey senderPublicKey = (ECPublicKey) senderKey.getPublic();
    ECPrivateKey senderPrivateKey = (ECPrivateKey) senderKey.getPrivate();

    KeyPair recipientKey = keyGen.generateKeyPair();
    ECPublicKey recipientPublicKey = (ECPublicKey) recipientKey.getPublic();
    ECPrivateKey recipientPrivateKey = (ECPrivateKey) recipientKey.getPrivate();

    PaymentMethodTokenSender sender =
        new PaymentMethodTokenSender.Builder()
            .senderId(senderId)
            .senderSigningKey(senderPrivateKey)
            .recipientId(recipientId)
            .recipientPublicKey(recipientPublicKey)
            .build();

    PaymentMethodTokenRecipient recipient =
        new PaymentMethodTokenRecipient.Builder()
            .senderId(senderId)
            .addSenderVerifyingKey(senderPublicKey)
            .recipientId(recipientId)
            .addRecipientPrivateKey(recipientPrivateKey)
            .build();

    String plaintext = "blah";
    assertEquals(plaintext, recipient.unseal(sender.seal(plaintext)));
  }

  @Test
  public void testWithKeysGeneratedByRecipientKeyGen() throws Exception {
    ECParameterSpec spec = EllipticCurves.getNistP256Params();
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
    keyGen.initialize(spec);
    String senderId = "foo";
    String recipientId = "bar";

    KeyPair senderKey = keyGen.generateKeyPair();
    ECPublicKey senderPublicKey = (ECPublicKey) senderKey.getPublic();
    ECPrivateKey senderPrivateKey = (ECPrivateKey) senderKey.getPrivate();

    // The keys here are generated by PaymentMethodTokenRecipientKeyGen.
    String recipientPrivateKey =
        "MEECAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQcEJzAlAgEBBCAP5/1502pXYdMion22yiWK"
            + "GoTBJN/wAAfdjBU6puyEMw==";
    String recipientPublicKey =
        "BJ995jnw2Ppn4BMP/ZKtlTOOIBQC+/L3PDcFRjowZuCkRqUZ/kGWE8c+zimZNHOZPzLB"
            + "NVGJ3V8M/fM4g4o02Mc=";

    PaymentMethodTokenSender sender =
        new PaymentMethodTokenSender.Builder()
            .senderId(senderId)
            .senderSigningKey(senderPrivateKey)
            .recipientId(recipientId)
            .rawUncompressedRecipientPublicKey(recipientPublicKey)
            .build();

    PaymentMethodTokenRecipient recipient =
        new PaymentMethodTokenRecipient.Builder()
            .senderId(senderId)
            .addSenderVerifyingKey(senderPublicKey)
            .recipientId(recipientId)
            .addRecipientPrivateKey(recipientPrivateKey)
            .build();

    String plaintext = "blah";
    assertEquals(plaintext, recipient.unseal(sender.seal(plaintext)));
  }

  private String newSignedIntermediateSigningKey() throws GeneralSecurityException {
    return new SenderIntermediateCertFactory.Builder()
        .protocolVersion(PaymentMethodTokenConstants.PROTOCOL_VERSION_EC_V2)
        .addSenderSigningKey(GOOGLE_SIGNING_EC_V2_PRIVATE_KEY_PKCS8_BASE64)
        .senderIntermediateSigningKey(GOOGLE_SIGNING_EC_V2_INTERMEDIATE_PUBLIC_KEY_X509_BASE64)
        .expiration(Instant.now().plus(Duration.standardDays(1)).getMillis())
        .build()
        .create();
  }
}
