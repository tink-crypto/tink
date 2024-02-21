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

package com.google.crypto.tink.aead;

import static com.google.crypto.tink.internal.TinkBugException.exceptionIsBug;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.Aead;
import com.google.crypto.tink.KeyManager;
import com.google.crypto.tink.KeyTemplate;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.SecretKeyAccess;
import com.google.crypto.tink.aead.internal.AesCtrHmacAeadProtoSerialization;
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
import com.google.crypto.tink.subtle.EncryptThenAuthenticate;
import com.google.crypto.tink.util.SecretBytes;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import javax.annotation.Nullable;

/**
 * This key manager generates new {@link AesCtrHmacAeadKey} keys and produces new instances of
 * {@link EncryptThenAuthenticate}.
 */
public final class AesCtrHmacAeadKeyManager {
  private static void validate(AesCtrHmacAeadParameters parameters)
      throws GeneralSecurityException {
    if (parameters.getAesKeySizeBytes() != 16 && parameters.getAesKeySizeBytes() != 32) {
      throw new GeneralSecurityException("AES key size must be 16 or 32 bytes");
    }
  }

  private static final PrimitiveConstructor<com.google.crypto.tink.aead.AesCtrHmacAeadKey, Aead>
      AES_CTR_HMAC_AEAD_PRIMITIVE_CONSTRUCTOR =
          PrimitiveConstructor.create(
              EncryptThenAuthenticate::create,
              com.google.crypto.tink.aead.AesCtrHmacAeadKey.class,
              Aead.class);

  private static final KeyManager<Aead> legacyKeyManager =
      LegacyKeyManagerImpl.create(
          getKeyType(),
          Aead.class,
          KeyMaterialType.SYMMETRIC,
          com.google.crypto.tink.proto.AesCtrHmacAeadKey.parser());

  static String getKeyType() {
    return "type.googleapis.com/google.crypto.tink.AesCtrHmacAeadKey";
  }

  @SuppressWarnings("InlineLambdaConstant") // We need a correct Object#equals in registration.
  private static final MutableKeyDerivationRegistry.InsecureKeyCreator<AesCtrHmacAeadParameters>
      KEY_DERIVER = AesCtrHmacAeadKeyManager::createAesCtrHmacAeadKeyFromRandomness;

  // To ensure that the derived key can provide key commitment, the AES-CTR key must be derived
  // before the HMAC key.
  // Consider the following malicious scenario using a brute-forced key InputStream with a 0 as
  // its 32nd byte:
  //     31 bytes || 1 byte of 0s || 16 bytes
  // We give this stream to party A, saying that it is 32-byte HMAC key || 16-byte AES key. We
  // also give this stream to party B, saying that it is 31-byte HMAC key || 16-byte AES key.
  // Since HMAC pads the key with zeroes, this same stream will lead to both parties using the
  // same HMAC key but different AES keys.
  @AccessesPartialKey
  static com.google.crypto.tink.aead.AesCtrHmacAeadKey createAesCtrHmacAeadKeyFromRandomness(
      AesCtrHmacAeadParameters parameters,
      InputStream stream,
      @Nullable Integer idRequirement,
      SecretKeyAccess access)
      throws GeneralSecurityException {
    return com.google.crypto.tink.aead.AesCtrHmacAeadKey.builder()
        .setParameters(parameters)
        .setIdRequirement(idRequirement)
        .setAesKeyBytes(Util.readIntoSecretBytes(stream, parameters.getAesKeySizeBytes(), access))
        .setHmacKeyBytes(Util.readIntoSecretBytes(stream, parameters.getHmacKeySizeBytes(), access))
        .build();
  }

  @SuppressWarnings("InlineLambdaConstant") // We need a correct Object#equals in registration.
  private static final MutableKeyCreationRegistry.KeyCreator<AesCtrHmacAeadParameters> KEY_CREATOR =
      AesCtrHmacAeadKeyManager::createAesCtrHmacAeadKey;

  @AccessesPartialKey
  static com.google.crypto.tink.aead.AesCtrHmacAeadKey createAesCtrHmacAeadKey(
      AesCtrHmacAeadParameters parameters, @Nullable Integer idRequirement)
      throws GeneralSecurityException {
    validate(parameters);
    return com.google.crypto.tink.aead.AesCtrHmacAeadKey.builder()
        .setParameters(parameters)
        .setIdRequirement(idRequirement)
        .setAesKeyBytes(SecretBytes.randomBytes(parameters.getAesKeySizeBytes()))
        .setHmacKeyBytes(SecretBytes.randomBytes(parameters.getHmacKeySizeBytes()))
        .build();
  }

  private static Map<String, Parameters> namedParameters() throws GeneralSecurityException {
        Map<String, Parameters> result = new HashMap<>();

        result.put("AES128_CTR_HMAC_SHA256", PredefinedAeadParameters.AES128_CTR_HMAC_SHA256);
        result.put(
            "AES128_CTR_HMAC_SHA256_RAW",
            AesCtrHmacAeadParameters.builder()
                .setAesKeySizeBytes(16)
                .setHmacKeySizeBytes(32)
                .setTagSizeBytes(16)
                .setIvSizeBytes(16)
                .setHashType(AesCtrHmacAeadParameters.HashType.SHA256)
                .setVariant(AesCtrHmacAeadParameters.Variant.NO_PREFIX)
                .build());

        result.put("AES256_CTR_HMAC_SHA256", PredefinedAeadParameters.AES256_CTR_HMAC_SHA256);
        result.put(
            "AES256_CTR_HMAC_SHA256_RAW",
            AesCtrHmacAeadParameters.builder()
                .setAesKeySizeBytes(32)
                .setHmacKeySizeBytes(32)
                .setTagSizeBytes(32)
                .setIvSizeBytes(16)
                .setHashType(AesCtrHmacAeadParameters.HashType.SHA256)
                .setVariant(AesCtrHmacAeadParameters.Variant.NO_PREFIX)
                .build());

        return Collections.unmodifiableMap(result);
  }

  public static void register(boolean newKeyAllowed) throws GeneralSecurityException {
    AesCtrHmacAeadProtoSerialization.register();
    MutablePrimitiveRegistry.globalInstance()
        .registerPrimitiveConstructor(AES_CTR_HMAC_AEAD_PRIMITIVE_CONSTRUCTOR);
    MutableParametersRegistry.globalInstance().putAll(namedParameters());
    MutableKeyDerivationRegistry.globalInstance().add(KEY_DERIVER, AesCtrHmacAeadParameters.class);
    MutableKeyCreationRegistry.globalInstance().add(KEY_CREATOR, AesCtrHmacAeadParameters.class);
    KeyManagerRegistry.globalInstance()
        .registerKeyManagerWithFipsCompatibility(
            legacyKeyManager,
            TinkFipsUtil.AlgorithmFipsCompatibility.ALGORITHM_REQUIRES_BORINGCRYPTO,
            newKeyAllowed);
  }

  /**
   * @return a {@link KeyTemplate} that generates new instances of AES-CTR-HMAC-AEAD keys with the
   *     following parameters:
   *     <ul>
   *       <li>AES key size: 16 bytes
   *       <li>AES CTR IV size: 16 byte
   *       <li>HMAC key size: 32 bytes
   *       <li>HMAC tag size: 16 bytes
   *       <li>HMAC hash function: SHA256
   *     </ul>
   */
  public static final KeyTemplate aes128CtrHmacSha256Template() {
    return exceptionIsBug(
        () ->
            KeyTemplate.createFrom(
                AesCtrHmacAeadParameters.builder()
                    .setAesKeySizeBytes(16)
                    .setHmacKeySizeBytes(32)
                    .setIvSizeBytes(16)
                    .setTagSizeBytes(16)
                    .setHashType(AesCtrHmacAeadParameters.HashType.SHA256)
                    .setVariant(AesCtrHmacAeadParameters.Variant.TINK)
                    .build()));
  }

  /**
   * @return a {@link KeyTemplate} that generates new instances of AES-CTR-HMAC-AEAD keys with the
   *     following parameters:
   *     <ul>
   *       <li>AES key size: 32 bytes
   *       <li>AES CTR IV size: 16 byte
   *       <li>HMAC key size: 32 bytes
   *       <li>HMAC tag size: 32 bytes
   *       <li>HMAC hash function: SHA256
   *     </ul>
   */
  public static final KeyTemplate aes256CtrHmacSha256Template() {
    return exceptionIsBug(
        () ->
            KeyTemplate.createFrom(
                AesCtrHmacAeadParameters.builder()
                    .setAesKeySizeBytes(32)
                    .setHmacKeySizeBytes(32)
                    .setIvSizeBytes(16)
                    .setTagSizeBytes(32)
                    .setHashType(AesCtrHmacAeadParameters.HashType.SHA256)
                    .setVariant(AesCtrHmacAeadParameters.Variant.TINK)
                    .build()));
  }

  private AesCtrHmacAeadKeyManager() {}
}
