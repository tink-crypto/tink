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
import com.google.crypto.tink.KeyTemplate;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.Registry;
import com.google.crypto.tink.SecretKeyAccess;
import com.google.crypto.tink.StreamingAead;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.internal.KeyTypeManager;
import com.google.crypto.tink.internal.MutableKeyDerivationRegistry;
import com.google.crypto.tink.internal.MutableParametersRegistry;
import com.google.crypto.tink.internal.MutablePrimitiveRegistry;
import com.google.crypto.tink.internal.PrimitiveConstructor;
import com.google.crypto.tink.internal.PrimitiveFactory;
import com.google.crypto.tink.internal.Util;
import com.google.crypto.tink.proto.AesGcmHkdfStreamingKey;
import com.google.crypto.tink.proto.AesGcmHkdfStreamingKeyFormat;
import com.google.crypto.tink.proto.AesGcmHkdfStreamingParams;
import com.google.crypto.tink.proto.HashType;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.streamingaead.internal.AesGcmHkdfStreamingProtoSerialization;
import com.google.crypto.tink.subtle.AesGcmHkdfStreaming;
import com.google.crypto.tink.subtle.Random;
import com.google.crypto.tink.subtle.Validators;
import com.google.protobuf.ByteString;
import com.google.protobuf.ExtensionRegistryLite;
import com.google.protobuf.InvalidProtocolBufferException;
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
public final class AesGcmHkdfStreamingKeyManager extends KeyTypeManager<AesGcmHkdfStreamingKey> {
  AesGcmHkdfStreamingKeyManager() {
    super(
        AesGcmHkdfStreamingKey.class,
        new PrimitiveFactory<StreamingAead, AesGcmHkdfStreamingKey>(StreamingAead.class) {
          @Override
          public StreamingAead getPrimitive(AesGcmHkdfStreamingKey key)
              throws GeneralSecurityException {
            return new AesGcmHkdfStreaming(
                key.getKeyValue().toByteArray(),
                StreamingAeadUtil.toHmacAlgo(key.getParams().getHkdfHashType()),
                key.getParams().getDerivedKeySize(),
                key.getParams().getCiphertextSegmentSize(),
                /* firstSegmentOffset= */ 0);
          }
        });
  }

  private static final int NONCE_PREFIX_IN_BYTES = 7;
  private static final int TAG_SIZE_IN_BYTES = 16;
  private static final PrimitiveConstructor<
          com.google.crypto.tink.streamingaead.AesGcmHkdfStreamingKey, StreamingAead>
      AES_GCM_HKDF_STREAMING_AEAD_PRIMITIVE_CONSTRUCTOR =
          PrimitiveConstructor.create(
              AesGcmHkdfStreaming::create,
              com.google.crypto.tink.streamingaead.AesGcmHkdfStreamingKey.class,
              StreamingAead.class);

  @Override
  public TinkFipsUtil.AlgorithmFipsCompatibility fipsStatus() {
    return TinkFipsUtil.AlgorithmFipsCompatibility.ALGORITHM_NOT_FIPS;
  }

  @Override
  public String getKeyType() {
    return "type.googleapis.com/google.crypto.tink.AesGcmHkdfStreamingKey";
  }

  @Override
  public int getVersion() {
    return 0;
  }

  @Override
  public KeyMaterialType keyMaterialType() {
    return KeyMaterialType.SYMMETRIC;
  }

  @Override
  public void validateKey(AesGcmHkdfStreamingKey key) throws GeneralSecurityException {
    Validators.validateVersion(key.getVersion(), getVersion());
    validateParams(key.getParams());
  }

  @Override
  public AesGcmHkdfStreamingKey parseKey(ByteString byteString)
      throws InvalidProtocolBufferException {
    return AesGcmHkdfStreamingKey.parseFrom(byteString, ExtensionRegistryLite.getEmptyRegistry());
  }

  @Override
  public KeyFactory<AesGcmHkdfStreamingKeyFormat, AesGcmHkdfStreamingKey> keyFactory() {
    return new KeyFactory<AesGcmHkdfStreamingKeyFormat, AesGcmHkdfStreamingKey>(
        AesGcmHkdfStreamingKeyFormat.class) {
      @Override
      public void validateKeyFormat(AesGcmHkdfStreamingKeyFormat format)
          throws GeneralSecurityException {
        if (format.getKeySize() < 16) {
          throw new GeneralSecurityException("key_size must be at least 16 bytes");
        }
        validateParams(format.getParams());
      }

      @Override
      public AesGcmHkdfStreamingKeyFormat parseKeyFormat(ByteString byteString)
          throws InvalidProtocolBufferException {
        return AesGcmHkdfStreamingKeyFormat.parseFrom(
            byteString, ExtensionRegistryLite.getEmptyRegistry());
      }

      @Override
      public AesGcmHkdfStreamingKey createKey(AesGcmHkdfStreamingKeyFormat format)
          throws GeneralSecurityException {
        return AesGcmHkdfStreamingKey.newBuilder()
            .setKeyValue(ByteString.copyFrom(Random.randBytes(format.getKeySize())))
            .setParams(format.getParams())
            .setVersion(getVersion())
            .build();
      }
    };
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

  private static void validateParams(AesGcmHkdfStreamingParams params)
      throws GeneralSecurityException {
    Validators.validateAesKeySize(params.getDerivedKeySize());
    if (params.getHkdfHashType() != HashType.SHA1
        && params.getHkdfHashType() != HashType.SHA256
        && params.getHkdfHashType() != HashType.SHA512) {
      throw new GeneralSecurityException("Invalid HKDF hash type");
    }
    if (params.getCiphertextSegmentSize()
        < params.getDerivedKeySize() + NONCE_PREFIX_IN_BYTES + TAG_SIZE_IN_BYTES + 2) {
      throw new GeneralSecurityException(
          "ciphertext_segment_size must be at least (derived_key_size + NONCE_PREFIX_IN_BYTES + "
              + "TAG_SIZE_IN_BYTES + 2)");
    }
  }

  public static void register(boolean newKeyAllowed) throws GeneralSecurityException {
    Registry.registerKeyManager(new AesGcmHkdfStreamingKeyManager(), newKeyAllowed);
    AesGcmHkdfStreamingProtoSerialization.register();
    MutableParametersRegistry.globalInstance().putAll(namedParameters());
    MutableKeyDerivationRegistry.globalInstance()
        .add(KEY_DERIVER, AesGcmHkdfStreamingParameters.class);
    MutablePrimitiveRegistry.globalInstance()
        .registerPrimitiveConstructor(AES_GCM_HKDF_STREAMING_AEAD_PRIMITIVE_CONSTRUCTOR);
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

}
