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

package com.google.crypto.tink.streamingaead;

import com.google.crypto.tink.proto.HashType;
import java.security.NoSuchAlgorithmException;

final class StreamingAeadUtil {
  /**
   * Returns the HMAC algorithm name corresponding to a hash type.
   *
   * @param hash the hash type
   * @return the JCE's HMAC algorithm name for the hash.
   */
  public static String toHmacAlgo(HashType hash) throws NoSuchAlgorithmException {
    switch (hash) {
      case SHA1:
        return "HmacSha1";
      case SHA224:
        return "HmacSha224";
      case SHA256:
        return "HmacSha256";
      case SHA384:
        return "HmacSha384";
      case SHA512:
        return "HmacSha512";
      default:
        throw new NoSuchAlgorithmException("hash unsupported for HMAC: " + hash);
    }
  }

  private StreamingAeadUtil() {}
}
