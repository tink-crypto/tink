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
import com.google.crypto.tink.SecretKeyAccess;
import com.google.crypto.tink.StreamingAead;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.internal.KeyManagerRegistry;
import com.google.crypto.tink.internal.LegacyKeyManagerImpl;
import com.google.crypto.tink.internal.MutableKeyCreationRegistry;
import com.google.crypto.tink.internal.MutableKeyDerivationRegistry;
import com.google.crypto.tink.internal.MutableParametersRegistry;
import com.google.crypto.tink.internal.MutablePrimitiveRegistry;
import com.google.crypto.tink.internal.PrimitiveConstructor;
import com.google.crypto.tink.internal.Util;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.streamingaead.internal.AesGcmHkdfStreamingProtoSerialization;
import com.google.crypto.tink.subtle.AesGcmHkdfStreaming;
import com.google.crypto.tink.util.SecretBytes;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import javax.annotation.Nullable;

/**
 * This key manager generates new {@code AesGcmHkdfStreamingKey} keys and produces new instances of
 * {@code AesGcmHkdfStreaming}.
 */
public final class AesGcmHkdfStreamingKeyManager {
  private static final PrimitiveConstructor<
          com.google.crypto.tink.streamingaead.AesGcmHkdfStreamingKey, StreamingAead>
      AES_GCM_HKDF_STREAMING_AEAD_PRIMITIVE_CONSTRUCTOR =
          PrimitiveConstructor.create(
              AesGcmHkdfStreaming::create,
              com.google.crypto.tink.streamingaead.AesGcmHkdfStreamingKey.class,
              StreamingAead.class);

  private static final KeyManager<StreamingAead> legacyKeyManager =
      LegacyKeyManagerImpl.create(
          getKeyType(),
          StreamingAead.class,
          KeyMaterialType.SYMMETRIC,
          com.google.crypto.tink.proto.AesGcmHkdfStreamingKey.parser());

  static String getKeyType() {
    return "type.googleapis.com/google.crypto.tink.AesGcmHkdfStreamingKey";
  }

  @SuppressWarnings("InlineLambdaConstant") // We need a correct Object#equals in registration.
  private static final MutableKeyCreationRegistry.KeyCreator<AesGcmHkdfStreamingParameters>
      KEY_CREATOR = AesGcmHkdfStreamingKeyManager::creatAesGcmHkdfStreamingKey;

  @AccessesPartialKey
  private static com.google.crypto.tink.streamingaead.AesGcmHkdfStreamingKey
      creatAesGcmHkdfStreamingKey(
          AesGcmHkdfStreamingParameters parameters, @Nullable Integer idRequirement)
          throws GeneralSecurityException {
    return com.google.crypto.tink.streamingaead.AesGcmHkdfStreamingKey.create(
        parameters, SecretBytes.randomBytes(parameters.getKeySizeBytes()));
  }

  @SuppressWarnings("InlineLambdaConstant") // We need a correct Object#equals in registration.
  private static final MutableKeyDerivationRegistry.InsecureKeyCreator<
          AesGcmHkdfStreamingParameters>
      KEY_DERIVER = AesGcmHkdfStreamingKeyManager::createAesGcmHkdfStreamingKeyFromRandomness;

  @AccessesPartialKey
  static com.google.crypto.tink.streamingaead.AesGcmHkdfStreamingKey
      createAesGcmHkdfStreamingKeyFromRandomness(
          AesGcmHkdfStreamingParameters parameters,
          InputStream stream,
          @Nullable Integer idRequirement,
          SecretKeyAccess access)
          throws GeneralSecurityException {
    return com.google.crypto.tink.streamingaead.AesGcmHkdfStreamingKey.create(
        parameters, Util.readIntoSecretBytes(stream, parameters.getKeySizeBytes(), access));
  }

  private static Map<String, Parameters> namedParameters() throws GeneralSecurityException {
        Map<String, Parameters> result = new HashMap<>();
        result.put("AES128_GCM_HKDF_4KB", PredefinedStreamingAeadParameters.AES128_GCM_HKDF_4KB);
        result.put("AES128_GCM_HKDF_1MB", PredefinedStreamingAeadParameters.AES128_GCM_HKDF_1MB);
        result.put("AES256_GCM_HKDF_4KB", PredefinedStreamingAeadParameters.AES256_GCM_HKDF_4KB);
        result.put("AES256_GCM_HKDF_1MB", PredefinedStreamingAeadParameters.AES256_GCM_HKDF_1MB);
        return Collections.unmodifiableMap(result);
  }

  public static void register(boolean newKeyAllowed) throws GeneralSecurityException {
    if (!TinkFipsUtil.AlgorithmFipsCompatibility.ALGORITHM_NOT_FIPS.isCompatible()) {
      throw new GeneralSecurityException(
          "Registering AES-GCM HKDF Streaming AEAD is not supported in FIPS mode");
    }
    AesGcmHkdfStreamingProtoSerialization.register();
    MutableParametersRegistry.globalInstance().putAll(namedParameters());
    MutableKeyDerivationRegistry.globalInstance()
        .add(KEY_DERIVER, AesGcmHkdfStreamingParameters.class);
    MutableKeyCreationRegistry.globalInstance()
        .add(KEY_CREATOR, AesGcmHkdfStreamingParameters.class);
    MutablePrimitiveRegistry.globalInstance()
        .registerPrimitiveConstructor(AES_GCM_HKDF_STREAMING_AEAD_PRIMITIVE_CONSTRUCTOR);
    KeyManagerRegistry.globalInstance().registerKeyManager(legacyKeyManager, newKeyAllowed);
  }

  /**
   * @return a {@link KeyTemplate} that generates new instances of AesGcmHkdfStreaming keys with the
   *     following parameters:
   *     <ul>
   *       <li>Size of the main key: 16 bytes
   *       <li>HKDF algo: HMAC-SHA256
   *       <li>Size of AES-GCM derived keys: 16 bytes
   *       <li>Ciphertext segment size: 4096 bytes
   *     </ul>
   */
  public static final KeyTemplate aes128GcmHkdf4KBTemplate() {
    return exceptionIsBug(
        () ->
            KeyTemplate.createFrom(
                AesGcmHkdfStreamingParameters.builder()
                    .setKeySizeBytes(16)
                    .setDerivedAesGcmKeySizeBytes(16)
                    .setCiphertextSegmentSizeBytes(4 * 1024)
                    .setHkdfHashType(AesGcmHkdfStreamingParameters.HashType.SHA256)
                    .build()));
  }

  /**
   * @return a {@link KeyTemplate} that generates new instances of AesGcmHkdfStreaming keys with the
   *     following parameters:
   *     <ul>
   *       <li>Size of the main key: 16 bytes
   *       <li>HKDF algo: HMAC-SHA256
   *       <li>Size of AES-GCM derived keys: 16 bytes
   *       <li>Ciphertext segment size: 1MB
   *     </ul>
   */
  public static final KeyTemplate aes128GcmHkdf1MBTemplate() {
    return exceptionIsBug(
        () ->
            KeyTemplate.createFrom(
                AesGcmHkdfStreamingParameters.builder()
                    .setKeySizeBytes(16)
                    .setDerivedAesGcmKeySizeBytes(16)
                    .setCiphertextSegmentSizeBytes(1024 * 1024)
                    .setHkdfHashType(AesGcmHkdfStreamingParameters.HashType.SHA256)
                    .build()));
  }

  /**
   * @return a {@link KeyTemplate} that generates new instances of AesGcmHkdfStreaming keys with the
   *     following parameters:
   *     <ul>
   *       <li>Size of the main key: 32 bytes
   *       <li>HKDF algo: HMAC-SHA256
   *       <li>Size of AES-GCM derived keys: 32 bytes
   *       <li>Ciphertext segment size: 4096 bytes
   *     </ul>
   */
  public static final KeyTemplate aes256GcmHkdf4KBTemplate() {
    return exceptionIsBug(
        () ->
            KeyTemplate.createFrom(
                AesGcmHkdfStreamingParameters.builder()
                    .setKeySizeBytes(32)
                    .setDerivedAesGcmKeySizeBytes(32)
                    .setCiphertextSegmentSizeBytes(4 * 1024)
                    .setHkdfHashType(AesGcmHkdfStreamingParameters.HashType.SHA256)
                    .build()));
  }

  /**
   * @return a {@link KeyTemplate} that generates new instances of AesGcmHkdfStreaming keys with the
   *     following parameters:
   *     <ul>
   *       <li>Size of the main key: 32 bytes
   *       <li>HKDF algo: HMAC-SHA256
   *       <li>Size of AES-GCM derived keys: 32 bytes
   *       <li>Ciphertext segment size: 1MB
   *     </ul>
   */
  public static final KeyTemplate aes256GcmHkdf1MBTemplate() {
    return exceptionIsBug(
        () ->
            KeyTemplate.createFrom(
                AesGcmHkdfStreamingParameters.builder()
                    .setKeySizeBytes(32)
                    .setDerivedAesGcmKeySizeBytes(32)
                    .setCiphertextSegmentSizeBytes(1024 * 1024)
                    .setHkdfHashType(AesGcmHkdfStreamingParameters.HashType.SHA256)
                    .build()));
  }

  private AesGcmHkdfStreamingKeyManager() {}
}
