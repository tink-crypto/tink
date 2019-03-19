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

package com.google.crypto.tink.subtle;

import com.google.crypto.tink.Mac;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;

/**
 * {@link Mac} implementations in JCE.
 *
 * @since 1.0.0
 */
public final class MacJce implements Mac {
  static final int MIN_TAG_SIZE_IN_BYTES = 10;
  static final int MIN_KEY_SIZE_IN_BYTES = 16;

  private javax.crypto.Mac mac;
  private final int digestSize;
  private final String algorithm;
  private final java.security.Key key;

  public MacJce(String algorithm, java.security.Key key, int digestSize)
      throws GeneralSecurityException {
    if (digestSize < MIN_TAG_SIZE_IN_BYTES) {
      throw new InvalidAlgorithmParameterException(
          "tag size too small, need at least " + MIN_TAG_SIZE_IN_BYTES + " bytes");
    }
    if (key.getEncoded().length < MIN_KEY_SIZE_IN_BYTES) {
      throw new InvalidAlgorithmParameterException(
          "key size too small, need at least " + MIN_KEY_SIZE_IN_BYTES + " bytes");
    }
    switch (algorithm) {
      case "HMACSHA1":
        if (digestSize > 20) {
          throw new InvalidAlgorithmParameterException("tag size too big");
        }
        break;
      case "HMACSHA256":
        if (digestSize > 32) {
          throw new InvalidAlgorithmParameterException("tag size too big");
        }
        break;
      case "HMACSHA512":
        if (digestSize > 64) {
          throw new InvalidAlgorithmParameterException("tag size too big");
        }
        break;
      default:
        throw new NoSuchAlgorithmException("unknown Hmac algorithm: " + algorithm);
    }

    this.algorithm = algorithm;
    this.digestSize = digestSize;
    this.key = key;
    this.mac = EngineFactory.MAC.getInstance(algorithm);
    mac.init(key);
  }

  @Override
  public byte[] computeMac(final byte[] data) throws GeneralSecurityException {
    javax.crypto.Mac tmp;
    try {
      // Cloning a mac is frequently fast and thread-safe.
      tmp = (javax.crypto.Mac) this.mac.clone();
    } catch (java.lang.CloneNotSupportedException ex) {
      // Unfortunately, the Mac interface in certain versions of Android is not clonable.
      tmp = EngineFactory.MAC.getInstance(this.algorithm);
      tmp.init(this.key);
    }
    tmp.update(data);
    byte[] digest = new byte[digestSize];
    System.arraycopy(tmp.doFinal(), 0, digest, 0, digestSize);
    return digest;
  }

  @Override
  public void verifyMac(final byte[] mac, final byte[] data) throws GeneralSecurityException {
    if (!Bytes.equal(computeMac(data), mac)) {
      throw new GeneralSecurityException("invalid MAC");
    }
  }
}
