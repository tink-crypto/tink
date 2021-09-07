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

package com.google.crypto.tink.apps.webpush;

import com.google.crypto.tink.subtle.Bytes;
import com.google.crypto.tink.subtle.Hkdf;
import java.security.GeneralSecurityException;

/** Various helpers. */
final class WebPushUtil {
  public static byte[] computeIkm(
      final byte[] ecdhSecret,
      final byte[] authSecret,
      final byte[] uaPublic,
      final byte[] asPublic)
      throws GeneralSecurityException {
    byte[] keyInfo = Bytes.concat(WebPushConstants.IKM_INFO, uaPublic, asPublic);
    return Hkdf.computeHkdf(
        WebPushConstants.HMAC_SHA256,
        ecdhSecret /* ikm */,
        authSecret /* salt */,
        keyInfo,
        WebPushConstants.IKM_SIZE);
  }

  public static byte[] computeCek(final byte[] ikm, final byte[] salt)
      throws GeneralSecurityException {
    return Hkdf.computeHkdf(
        WebPushConstants.HMAC_SHA256,
        ikm,
        salt,
        WebPushConstants.CEK_INFO,
        WebPushConstants.CEK_KEY_SIZE);
  }

  public static byte[] computeNonce(final byte[] ikm, final byte[] salt)
      throws GeneralSecurityException {
    return Hkdf.computeHkdf(
        WebPushConstants.HMAC_SHA256,
        ikm,
        salt,
        WebPushConstants.NONCE_INFO,
        WebPushConstants.NONCE_SIZE);
  }

  private WebPushUtil() {}
}
