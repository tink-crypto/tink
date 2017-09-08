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

import com.google.crypto.tink.subtle.EllipticCurves;
import java.nio.charset.StandardCharsets;

/** Various constants. */
class PaymentMethodTokenConstants {
  public static final String GOOGLE_SENDER_ID = "Google";
  public static final String HMAC_SHA256_ALGO = "HmacSha256";
  public static final byte[] HKDF_EMPTY_SALT = new byte[0];
  public static final byte[] GOOGLE_CONTEXT_INFO_ECV1 = "Google".getBytes(StandardCharsets.UTF_8);
  public static final String AES_CTR_ALGO = "AES/CTR/NoPadding";
  public static final int AES_CTR_KEY_SIZE = 16;
  // Zero IV is fine here because each encryption uses a unique key.
  public static final byte[] AES_CTR_ZERO_IV = new byte[16];
  public static final int HMAC_SHA256_KEY_SIZE = 16;
  public static final EllipticCurves.PointFormatType UNCOMPRESSED_POINT_FORMAT =
      EllipticCurves.PointFormatType.UNCOMPRESSED;
  public static final String PROTOCOL_VERSION_EC_V1 = "ECv1";
  public static final String ECDSA_SHA256_SIGNING_ALGO = "SHA256WithECDSA";

  public static final String JSON_ENCRYPTED_MESSAGE_KEY = "encryptedMessage";
  public static final String JSON_TAG_KEY = "tag";
  public static final String JSON_EPHEMERAL_PUBLIC_KEY = "ephemeralPublicKey";
  public static final String JSON_SIGNATURE_KEY = "signature";
  public static final String JSON_SIGNED_MESSAGE_KEY = "signedMessage";
  public static final String JSON_PROTOCOL_VERSION_KEY = "protocolVersion";
  public static final String JSON_MESSAGE_EXPIRATION_KEY = "messageExpiration";
}
