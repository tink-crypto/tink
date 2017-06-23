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
// See the License for the specified language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

package com.google.crypto.tink;

import com.google.crypto.tink.aead.GcpKmsAeadKeyManager;
import com.google.crypto.tink.proto.GcpKmsAeadKey;
import com.google.crypto.tink.proto.KeyData;

/**
 * Test helpers for envelope encryption.
 * These functions cannot be in TestUtil because they depend on classes
 * that are not available on the Android build.
 */
public class EnvelopeTestUtil {
    /**
   * @return a {@code KeyData} containing a {@code GcpKmsAeadKey}.
   */
  public static KeyData createGcpKmsAeadKeyData(String kmsKeyUri)
      throws Exception {
    GcpKmsAeadKey keyProto = GcpKmsAeadKey.newBuilder()
        .setKmsKeyUri(kmsKeyUri)
        .build();
    return TestUtil.createKeyData(
        keyProto,
        GcpKmsAeadKeyManager.TYPE_URL,
        KeyData.KeyMaterialType.REMOTE);
  }
}
