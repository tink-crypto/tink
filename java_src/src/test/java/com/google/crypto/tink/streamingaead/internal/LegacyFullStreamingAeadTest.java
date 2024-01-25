// Copyright 2023 Google LLC
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

package com.google.crypto.tink.streamingaead.internal;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.StreamingAead;
import com.google.crypto.tink.internal.LegacyProtoKey;
import com.google.crypto.tink.internal.MutablePrimitiveRegistry;
import com.google.crypto.tink.internal.MutableSerializationRegistry;
import com.google.crypto.tink.internal.PrimitiveConstructor;
import com.google.crypto.tink.internal.ProtoKeySerialization;
import com.google.crypto.tink.streamingaead.AesGcmHkdfStreamingKey;
import com.google.crypto.tink.streamingaead.AesGcmHkdfStreamingParameters;
import com.google.crypto.tink.streamingaead.AesGcmHkdfStreamingParameters.HashType;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.testing.StreamingTestUtil;
import com.google.crypto.tink.util.SecretBytes;
import org.junit.BeforeClass;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

@RunWith(Theories.class)
@AccessesPartialKey
public class LegacyFullStreamingAeadTest {

  @BeforeClass
  public static void setUp() throws Exception {
    LegacyAesGcmHkdfStreamingTestKeyManager.register();
    AesGcmHkdfStreamingProtoSerialization.register();
    // This is to ensure that the tests indeed get the objects we are testing for.
    MutablePrimitiveRegistry.globalInstance()
        .registerPrimitiveConstructor(
            PrimitiveConstructor.create(
                (LegacyProtoKey key) ->
                    (LegacyFullStreamingAead) LegacyFullStreamingAead.create(key),
                LegacyProtoKey.class,
                LegacyFullStreamingAead.class));
  }

  @Theory
  public void createdPrimitive_encryptDecrypt_works() throws Exception {
    AesGcmHkdfStreamingKey key =
        AesGcmHkdfStreamingKey.create(
            AesGcmHkdfStreamingParameters.builder()
                .setHkdfHashType(HashType.SHA256)
                .setKeySizeBytes(32)
                .setDerivedAesGcmKeySizeBytes(16)
                .setCiphertextSegmentSizeBytes(100)
                .build(),
            SecretBytes.copyFrom(
                Hex.decode("000102030405060708090a0b0c0d0e0f00112233445566778899aabbccddeeff"),
                InsecureSecretKeyAccess.get()));
    StreamingAead legacyStreamingAead = LegacyFullStreamingAead.create(new LegacyProtoKey(
        MutableSerializationRegistry.globalInstance()
            .serializeKey(
                key, ProtoKeySerialization.class, InsecureSecretKeyAccess.get()),
        InsecureSecretKeyAccess.get()));

    StreamingTestUtil.testEncryptDecrypt(legacyStreamingAead, 0, 20, 20);
  }
}
