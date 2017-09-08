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

import com.google.crypto.tink.subtle.EllipticCurves;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
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
  /**
   * Created with:
   *
   * <pre>
   * openssl pkcs8 -topk8 -inform PEM -outform PEM -in google-key.pem -nocrypt
   * </pre>
   */
  private static final String GOOGLE_SIGNING_PRIVATE_KEY_PKCS8_BASE64 =
      "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgZj/Dldxz8fvKVF5O"
          + "TeAtK6tY3G1McmvhMppe6ayW6GahRANCAAQ9icfBLy56BYB7BC2XGLOYsXKfAdzF"
          + "FPU8rTtwMDr8LixetUjVLNkJTHxTxLQuMytPqKt39Vbtt7czPq3+yu1F";
  /**
   * Public key value created with:
   *
   * <pre>
   * openssl ec -in google-key.pem -inform PEM -outform PEM -pubout
   * </pre>
   */
  private static final String GOOGLE_VERIFYING_PUBLIC_KEYS_JSON =
      "{\n"
          + "  \"keys\": [\n"
          + "    {\n"
          + "      \"keyValue\": \"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEPYnHwS8uegWAewQtlxizmLFynw"
          + "HcxRT1PK07cDA6/C4sXrVI1SzZCUx8U8S0LjMrT6ird/VW7be3Mz6t/srtRQ==\",\n"
          + "      \"protocolVersion\": \"ECv1\"\n"
          + "    },\n"
          + "  ],\n"
          + "}";

  private static final String RECIPIENT_ID = "someRecipient";

  @Test
  public void testWithPrecomputedKeys() throws Exception {
    PaymentMethodTokenSender sender =
        new PaymentMethodTokenSender.Builder()
            .senderSigningKey(GOOGLE_SIGNING_PRIVATE_KEY_PKCS8_BASE64)
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
}
