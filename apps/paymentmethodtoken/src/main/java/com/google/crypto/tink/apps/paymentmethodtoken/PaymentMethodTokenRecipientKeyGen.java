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

import com.google.crypto.tink.subtle.Base64;
import com.google.crypto.tink.subtle.EllipticCurves;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.interfaces.ECPublicKey;

/**
 * A util that generates key pairs for the recipient side of <a
 * href="https://developers.google.com/android-pay/integration/payment-token-cryptography">Google
 * Payment Method Token</a>.
 *
 * <h3>Usage</h3>
 *
 * <pre>
 * bazel build apps/paymentmethodtoken/...
 * ./bazel-bin/apps/paymentmethodtoken/recipientkeygen
 * </pre>
 *
 * <p>Running that command will generate a fresh key pair. The private/public key can be found in
 * private_key.bin/public_key.bin. The content of private_key.bin can be passed to {@link
 * PaymentMethodTokenRecipient.Builder#addRecipientPrivateKey} and the content of public_key.bin can
 * be passed to {@link PaymentMethodTokenSender.Builder#rawUncompressedRecipientPublicKey}.
 */
public final class PaymentMethodTokenRecipientKeyGen {
  private static final String PRIVATE_KEY_FILE = "private_key.bin";

  private static final String PUBLIC_KEY_FILE = "public_key.bin";

  private static void generateKey() throws GeneralSecurityException, IOException {
    KeyPair keyPair = EllipticCurves.generateKeyPair(PaymentMethodTokenConstants.P256_CURVE_TYPE);
    writeBase64(PRIVATE_KEY_FILE, keyPair.getPrivate().getEncoded());

    ECPublicKey publicKey = (ECPublicKey) keyPair.getPublic();
    writeBase64(
        PUBLIC_KEY_FILE,
        EllipticCurves.pointEncode(
            PaymentMethodTokenConstants.P256_CURVE_TYPE,
            PaymentMethodTokenConstants.UNCOMPRESSED_POINT_FORMAT,
            publicKey.getW()));
  }

  private static void writeBase64(String pathname, byte[] content) throws IOException {
    File out = new File(pathname);
    if (out.exists()) {
      System.out.println("Please make sure that " + pathname + " does not exist.");
      System.exit(-1);
    }
    FileOutputStream stream = new FileOutputStream(out);
    stream.write(Base64.encode(content, Base64.DEFAULT | Base64.NO_WRAP));
    stream.close();
  }

  public static void main(String[] args) throws GeneralSecurityException, IOException {
    System.out.println("Generating key....");
    generateKey();
    System.out.println("done.");
  }
}
