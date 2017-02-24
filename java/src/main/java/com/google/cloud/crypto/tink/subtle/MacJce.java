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

package com.google.cloud.crypto.tink.subtle;

import com.google.cloud.crypto.tink.Mac;
import java.security.GeneralSecurityException;

/**
 * Mac implementations in JCE.
 */
public class MacJce implements Mac {
  private javax.crypto.Mac mac;
  private final int digestSize;

  private javax.crypto.Mac instance() throws GeneralSecurityException {
    try {
      return (javax.crypto.Mac) mac.clone();
    } catch (java.lang.CloneNotSupportedException ex) {
      throw new GeneralSecurityException(ex);
    }
  }

  public MacJce(String algorithm, java.security.Key key, int digestSize)
      throws GeneralSecurityException {
    this.mac = javax.crypto.Mac.getInstance(algorithm);
    this.digestSize = digestSize;
    mac.init(key);
  }

  @Override
  public byte[] computeMac(final byte[] data) throws GeneralSecurityException {
    javax.crypto.Mac tmp = instance();
    tmp.update(data);
    byte[] digest = new byte[digestSize];
    System.arraycopy(tmp.doFinal(), 0, digest, 0, digestSize);
    return digest;
  }

  @Override
  public boolean verifyMac(final byte[] mac, final byte[] data)
      throws GeneralSecurityException {
    return Util.arrayEquals(computeMac(data), mac);
  }
};
