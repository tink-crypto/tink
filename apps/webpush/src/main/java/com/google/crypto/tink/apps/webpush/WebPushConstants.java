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

import com.google.crypto.tink.subtle.EllipticCurves;
import java.nio.charset.Charset;

/** Various constants. */
final class WebPushConstants {
  static final Charset UTF_8 = Charset.forName("UTF-8");
  static final int AUTH_SECRET_SIZE = 16;
  static final int IKM_SIZE = 32;
  static final int CEK_KEY_SIZE = 16;
  static final int NONCE_SIZE = 12;
  static final byte[] IKM_INFO =
      new byte[] {'W', 'e', 'b', 'P', 'u', 's', 'h', ':', ' ', 'i', 'n', 'f', 'o', (byte) 0};
  static final byte[] CEK_INFO =
      new byte[] {
        'C', 'o', 'n', 't', 'e', 'n', 't', '-', 'E', 'n', 'c', 'o', 'd', 'i', 'n', 'g', ':', ' ',
        'a', 'e', 's', '1', '2', '8', 'g', 'c', 'm', (byte) 0
      };
  static final byte[] NONCE_INFO =
      new byte[] {
        'C', 'o', 'n', 't', 'e', 'n', 't', '-', 'E', 'n', 'c', 'o', 'd', 'i', 'n', 'g', ':', ' ',
        'n', 'o', 'n', 'c', 'e', (byte) 0
      };

  static final int SALT_SIZE = 16;
  static final int RECORD_SIZE_LEN = 4;
  static final int PUBLIC_KEY_SIZE_LEN = 1;
  static final int PUBLIC_KEY_SIZE = 65;
  //   * salt:                    16
  //   * record size:              4
  //   * public key size:          1
  //   * uncompressed public key: 65
  //   * total                  : 86
  static final int CONTENT_CODING_HEADER_SIZE =
      SALT_SIZE + RECORD_SIZE_LEN + PUBLIC_KEY_SIZE_LEN + PUBLIC_KEY_SIZE;

  // the byte 0x2 separating the payload and the padding
  static final byte PADDING_DELIMITER_BYTE = (byte) 2;
  static final int PADDING_DELIMETER_SIZE = 1;
  static final int DEFAULT_PADDING_SIZE = 0;
  static final int TAG_SIZE = 16;
  //   * content coding header:   86
  //   * padding delimeter:        1
  //   * AES-GCM tag size:        16
  //   * Total:                  103
  static final int CIPHERTEXT_OVERHEAD =
      CONTENT_CODING_HEADER_SIZE + PADDING_DELIMETER_SIZE + DEFAULT_PADDING_SIZE + TAG_SIZE;

  static final int MAX_CIPHERTEXT_SIZE = 4096;

  static final String HMAC_SHA256 = "HMACSHA256";
  static final EllipticCurves.PointFormatType UNCOMPRESSED_POINT_FORMAT =
      EllipticCurves.PointFormatType.UNCOMPRESSED;
  static final EllipticCurves.CurveType NIST_P256_CURVE_TYPE = EllipticCurves.CurveType.NIST_P256;

  private WebPushConstants() {}
}
