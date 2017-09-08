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
import com.google.crypto.tink.subtle.Bytes;
import com.google.crypto.tink.subtle.EllipticCurves;
import com.google.crypto.tink.subtle.EngineFactory;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/** Various helpers. */
class PaymentMethodTokenUtil {

  public static ECPublicKey rawUncompressedEcPublicKey(String rawUncompressedPublicKey)
      throws GeneralSecurityException {
    ECPoint point =
        EllipticCurves.ecPointDecode(
            EllipticCurves.getNistP256Params().getCurve(),
            EllipticCurves.PointFormatType.UNCOMPRESSED,
            Base64.decode(rawUncompressedPublicKey));
    ECPublicKeySpec pubSpec = new ECPublicKeySpec(point, EllipticCurves.getNistP256Params());
    KeyFactory kf = EngineFactory.KEY_FACTORY.getInstance("EC");
    return (ECPublicKey) kf.generatePublic(pubSpec);
  }

  public static ECPublicKey x509EcPublicKey(String x509PublicKey) throws GeneralSecurityException {
    KeyFactory kf = EngineFactory.KEY_FACTORY.getInstance("EC");
    return (ECPublicKey) kf.generatePublic(new X509EncodedKeySpec(Base64.decode(x509PublicKey)));
  }

  public static ECPrivateKey pkcs8EcPrivateKey(String pkcs8PrivateKey)
      throws GeneralSecurityException {
    KeyFactory kf = EngineFactory.KEY_FACTORY.getInstance("EC");
    return (ECPrivateKey)
        kf.generatePrivate(new PKCS8EncodedKeySpec(Base64.decode(pkcs8PrivateKey)));
  }

  public static byte[] toLengthValue(String... chunks) throws GeneralSecurityException {
    byte[] out = new byte[0];
    for (String chunk : chunks) {
      byte[] bytes = chunk.getBytes(StandardCharsets.UTF_8);
      out = Bytes.concat(out, Bytes.intToByteArray(4, bytes.length));
      out = Bytes.concat(out, bytes);
    }
    return out;
  }

  static byte[] aesCtr(final byte[] encryptionKey, final byte[] message)
      throws GeneralSecurityException {
    Cipher cipher = EngineFactory.CIPHER.getInstance(PaymentMethodTokenConstants.AES_CTR_ALGO);
    cipher.init(
        Cipher.ENCRYPT_MODE,
        new SecretKeySpec(encryptionKey, "AES"),
        new IvParameterSpec(PaymentMethodTokenConstants.AES_CTR_ZERO_IV));
    return cipher.doFinal(message);
  }

  static byte[] hmacSha256(final byte[] macKey, final byte[] encryptedMessage)
      throws GeneralSecurityException {
    SecretKeySpec key = new SecretKeySpec(macKey, PaymentMethodTokenConstants.HMAC_SHA256_ALGO);
    Mac mac = EngineFactory.MAC.getInstance(PaymentMethodTokenConstants.HMAC_SHA256_ALGO);
    mac.init(key);
    return mac.doFinal(encryptedMessage);
  }
}
