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
// //////////////////////////////////////////////////////////////////////////////

package com.google.crypto.tink.streamingaead;

import static com.google.crypto.tink.internal.TinkBugException.exceptionIsBug;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.KeyManager;
import com.google.crypto.tink.KeyTemplate;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.Registry;
import com.google.crypto.tink.StreamingAead;
import com.google.crypto.tink.internal.LegacyKeyManagerImpl;
import com.google.crypto.tink.internal.MutableKeyCreationRegistry;
import com.google.crypto.tink.internal.MutableParametersRegistry;
import com.google.crypto.tink.internal.MutablePrimitiveRegistry;
import com.google.crypto.tink.internal.PrimitiveConstructor;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.subtle.AesCtrHmacStreaming;
import com.google.crypto.tink.util.SecretBytes;
import java.security.GeneralSecurityException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import javax.annotation.Nullable;

/**
 * This key manager generates new {@code AesCtrHmacStreamingKey} keys and produces new instances of
 * {@code AesCtrHmacStreaming}.
 */
public final class AesCtrHmacStreamingKeyManager {

  private static final PrimitiveConstructor<
          com.google.crypto.tink.streamingaead.AesCtrHmacStreamingKey, StreamingAead>
      AES_CTR_HMAC_STREAMING_AEAD_PRIMITIVE_CONSTRUCTOR =
          PrimitiveConstructor.create(
              AesCtrHmacStreaming::create,
              com.google.crypto.tink.streamingaead.AesCtrHmacStreamingKey.class,
              StreamingAead.class);

  @SuppressWarnings("InlineLambdaConstant") // We need a correct Object#equals in registration.
  private static final MutableKeyCreationRegistry.KeyCreator<AesCtrHmacStreamingParameters>
      KEY_CREATOR = AesCtrHmacStreamingKeyManager::createAesCtrHmacStreamingKey;

  @AccessesPartialKey
  private static com.google.crypto.tink.streamingaead.AesCtrHmacStreamingKey
      createAesCtrHmacStreamingKey(
          AesCtrHmacStreamingParameters parameters, @Nullable Integer idRequirement)
          throws GeneralSecurityException {
    return com.google.crypto.tink.streamingaead.AesCtrHmacStreamingKey.create(
        parameters, SecretBytes.randomBytes(parameters.getKeySizeBytes()));
  }

  private static final KeyManager<StreamingAead> legacyKeyManager =
      LegacyKeyManagerImpl.create(
          getKeyType(),
          StreamingAead.class,
          KeyMaterialType.SYMMETRIC,
          com.google.crypto.tink.proto.AesCtrHmacStreamingKey.parser());

  static String getKeyType() {
    return "type.googleapis.com/google.crypto.tink.AesCtrHmacStreamingKey";
  }

  private static Map<String, Parameters> namedParameters() throws GeneralSecurityException {
        Map<String, Parameters> result = new HashMap<>();
        result.put(
            "AES128_CTR_HMAC_SHA256_4KB",
            PredefinedStreamingAeadParameters.AES128_CTR_HMAC_SHA256_4KB);
        result.put(
            "AES128_CTR_HMAC_SHA256_1MB",
            PredefinedStreamingAeadParameters.AES128_CTR_HMAC_SHA256_1MB);
        result.put(
            "AES256_CTR_HMAC_SHA256_4KB",
            PredefinedStreamingAeadParameters.AES256_CTR_HMAC_SHA256_4KB);
        result.put(
            "AES256_CTR_HMAC_SHA256_1MB",
            PredefinedStreamingAeadParameters.AES256_CTR_HMAC_SHA256_1MB);
        return Collections.unmodifiableMap(result);
  }

  public static void register(boolean newKeyAllowed) throws GeneralSecurityException {
    AesCtrHmacStreamingProtoSerialization.register();
    MutableParametersRegistry.globalInstance().putAll(namedParameters());
    MutableKeyCreationRegistry.globalInstance()
        .add(KEY_CREATOR, AesCtrHmacStreamingParameters.class);
    MutablePrimitiveRegistry.globalInstance()
        .registerPrimitiveConstructor(AES_CTR_HMAC_STREAMING_AEAD_PRIMITIVE_CONSTRUCTOR);
    Registry.registerKeyManager(legacyKeyManager, newKeyAllowed);
  }

  /**
   * @return a {@link KeyTemplate} that generates new instances of AesCtrHmacStreaming keys with the
   *     following parameters:
   *     <ul>
   *       <li>Size of the main key: 16 bytes
   *       <li>HKDF algo: HMAC-SHA256
   *       <li>Size of AES-CTR derived keys: 16 bytes
   *       <li>Tag algo: HMAC-SHA256
   *       <li>Tag size: 32 bytes
   *       <li>Ciphertext segment size: 4096
   *     </ul>
   */
  public static final KeyTemplate aes128CtrHmacSha2564KBTemplate() {
    return exceptionIsBug(
        () ->
            KeyTemplate.createFrom(
                AesCtrHmacStreamingParameters.builder()
                    .setKeySizeBytes(16)
                    .setDerivedKeySizeBytes(16)
                    .setHkdfHashType(AesCtrHmacStreamingParameters.HashType.SHA256)
                    .setHmacHashType(AesCtrHmacStreamingParameters.HashType.SHA256)
                    .setHmacTagSizeBytes(32)
                    .setCiphertextSegmentSizeBytes(4 * 1024)
                    .build()));
  }

  /**
   * @return a {@link KeyTemplate} that generates new instances of AesCtrHmacStreaming keys with the
   *     following parameters:
   *     <ul>
   *       <li>Size of the main key: 16 bytes
   *       <li>HKDF algo: HMAC-SHA256
   *       <li>Size of AES-CTR derived keys: 16 bytes
   *       <li>Tag algo: HMAC-SHA256
   *       <li>Tag size: 32 bytes
   *       <li>Ciphertext segment size: 1MB
   *     </ul>
   */
  public static final KeyTemplate aes128CtrHmacSha2561MBTemplate() {
    return exceptionIsBug(
        () ->
            KeyTemplate.createFrom(
                AesCtrHmacStreamingParameters.builder()
                    .setKeySizeBytes(16)
                    .setDerivedKeySizeBytes(16)
                    .setHkdfHashType(AesCtrHmacStreamingParameters.HashType.SHA256)
                    .setHmacHashType(AesCtrHmacStreamingParameters.HashType.SHA256)
                    .setHmacTagSizeBytes(32)
                    .setCiphertextSegmentSizeBytes(1024 * 1024)
                    .build()));
  }

  /**
   * @return a {@link KeyTemplate} that generates new instances of AesCtrHmacStreaming keys with the
   *     following parameters:
   *     <ul>
   *       <li>Size of the main key: 32 bytes
   *       <li>HKDF algo: HMAC-SHA256
   *       <li>Size of AES-CTR derived keys: 32 bytes
   *       <li>Tag algo: HMAC-SHA256
   *       <li>Tag size: 32 bytes
   *       <li>Ciphertext segment size: 4096
   *     </ul>
   */
  public static final KeyTemplate aes256CtrHmacSha2564KBTemplate() {
    return exceptionIsBug(
        () ->
            KeyTemplate.createFrom(
                AesCtrHmacStreamingParameters.builder()
                    .setKeySizeBytes(32)
                    .setDerivedKeySizeBytes(32)
                    .setHkdfHashType(AesCtrHmacStreamingParameters.HashType.SHA256)
                    .setHmacHashType(AesCtrHmacStreamingParameters.HashType.SHA256)
                    .setHmacTagSizeBytes(32)
                    .setCiphertextSegmentSizeBytes(4 * 1024)
                    .build()));
  }

  /**
   * @return a {@link KeyTemplate} that generates new instances of AesCtrHmacStreaming keys with the
   *     following parameters:
   *     <ul>
   *       <li>Size of the main key: 32 bytes
   *       <li>HKDF algo: HMAC-SHA256
   *       <li>Size of AES-CTR derived keys: 32 bytes
   *       <li>Tag algo: HMAC-SHA256
   *       <li>Tag size: 32 bytes
   *       <li>Ciphertext segment size: 1MB
   *     </ul>
   */
  public static final KeyTemplate aes256CtrHmacSha2561MBTemplate() {
    return exceptionIsBug(
        () ->
            KeyTemplate.createFrom(
                AesCtrHmacStreamingParameters.builder()
                    .setKeySizeBytes(32)
                    .setDerivedKeySizeBytes(32)
                    .setHkdfHashType(AesCtrHmacStreamingParameters.HashType.SHA256)
                    .setHmacHashType(AesCtrHmacStreamingParameters.HashType.SHA256)
                    .setHmacTagSizeBytes(32)
                    .setCiphertextSegmentSizeBytes(1024 * 1024)
                    .build()));
  }

  private AesCtrHmacStreamingKeyManager() {}
}
