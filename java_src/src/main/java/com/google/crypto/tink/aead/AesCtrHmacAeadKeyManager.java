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
import com.google.crypto.tink.KeyTemplate;
import com.google.crypto.tink.Mac;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.Registry;
import com.google.crypto.tink.SecretKeyAccess;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.internal.KeyTypeManager;
import com.google.crypto.tink.internal.MutableKeyDerivationRegistry;
import com.google.crypto.tink.internal.MutableParametersRegistry;
import com.google.crypto.tink.internal.MutablePrimitiveRegistry;
import com.google.crypto.tink.internal.PrimitiveConstructor;
import com.google.crypto.tink.internal.PrimitiveFactory;
import com.google.crypto.tink.internal.Util;
import com.google.crypto.tink.mac.HmacKeyManager;
import com.google.crypto.tink.proto.AesCtrHmacAeadKey;
import com.google.crypto.tink.proto.AesCtrHmacAeadKeyFormat;
import com.google.crypto.tink.proto.AesCtrKey;
import com.google.crypto.tink.proto.AesCtrParams;
import com.google.crypto.tink.proto.HmacKey;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.subtle.AesCtrJceCipher;
import com.google.crypto.tink.subtle.EncryptThenAuthenticate;
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
 * This key manager generates new {@link AesCtrHmacAeadKey} keys and produces new instances of
 * {@link EncryptThenAuthenticate}.
 */
public final class AesCtrHmacAeadKeyManager extends KeyTypeManager<AesCtrHmacAeadKey> {
  private static final PrimitiveConstructor<com.google.crypto.tink.aead.AesCtrHmacAeadKey, Aead>
      AES_CTR_HMAC_AEAD_PRIMITIVE_CONSTRUCTOR =
          PrimitiveConstructor.create(
              EncryptThenAuthenticate::create,
              com.google.crypto.tink.aead.AesCtrHmacAeadKey.class,
              Aead.class);

  // In counter mode each message is encrypted with an initialization vector (IV) that must be
  // unique. If one single IV is ever used to encrypt two or more messages, the confidentiality of
  // these messages might be lost. This cipher uses a randomly generated IV for each message. The
  // birthday paradox says that if one encrypts 2^k messages, the probability that the random IV
  // will repeat is roughly 2^{2k - t}, where t is the size in bits of the IV. Thus with 96-bit
  // (12-byte) IV, if one encrypts 2^32 messages the probability of IV collision is less than
  // 2^-33 (i.e., less than one in eight billion).
  private static final int MIN_AES_CTR_IV_SIZE_IN_BYTES = 12;

  AesCtrHmacAeadKeyManager() {
    super(
        AesCtrHmacAeadKey.class,
        new PrimitiveFactory<Aead, AesCtrHmacAeadKey>(Aead.class) {
          @Override
          public Aead getPrimitive(AesCtrHmacAeadKey key) throws GeneralSecurityException {
            return new EncryptThenAuthenticate(
                new AesCtrJceCipher(
                    key.getAesCtrKey().getKeyValue().toByteArray(),
                    key.getAesCtrKey().getParams().getIvSize()),
                new HmacKeyManager().getPrimitive(key.getHmacKey(), Mac.class),
                key.getHmacKey().getParams().getTagSize());
          }
        });
  }

  // Static so we don't have to construct the object and handle the exception when we need the
  // key type.
  @Override
  public String getKeyType() {
    return "type.googleapis.com/google.crypto.tink.AesCtrHmacAeadKey";
  }

  @Override
  public int getVersion() {
    return 0;
  }

  private int getAesCtrVersion() {
    return 0;
  }

  @Override
  public KeyMaterialType keyMaterialType() {
    return KeyMaterialType.SYMMETRIC;
  }

  @Override
  public void validateKey(AesCtrHmacAeadKey key) throws GeneralSecurityException {
    // Validate overall.
    Validators.validateVersion(key.getVersion(), getVersion());

    // Validate AesCtrKey.
    AesCtrKey aesCtrKey = key.getAesCtrKey();
    Validators.validateVersion(aesCtrKey.getVersion(), getAesCtrVersion());
    Validators.validateAesKeySize(aesCtrKey.getKeyValue().size());
    AesCtrParams aesCtrParams = aesCtrKey.getParams();
    if (aesCtrParams.getIvSize() < MIN_AES_CTR_IV_SIZE_IN_BYTES || aesCtrParams.getIvSize() > 16) {
      throw new GeneralSecurityException("invalid AES STR IV size");
    }

    // Validate HmacKey.
    new HmacKeyManager().validateKey(key.getHmacKey());
  }

  @Override
  public AesCtrHmacAeadKey parseKey(ByteString byteString) throws InvalidProtocolBufferException {
    return AesCtrHmacAeadKey.parseFrom(byteString, ExtensionRegistryLite.getEmptyRegistry());
  }

  @Override
  public KeyFactory<AesCtrHmacAeadKeyFormat, AesCtrHmacAeadKey> keyFactory() {
    return new KeyFactory<AesCtrHmacAeadKeyFormat, AesCtrHmacAeadKey>(
        AesCtrHmacAeadKeyFormat.class) {
      @Override
      public void validateKeyFormat(AesCtrHmacAeadKeyFormat format)
          throws GeneralSecurityException {
        // Validate AesCtrKeyFormat.
        Validators.validateAesKeySize(format.getAesCtrKeyFormat().getKeySize());
        AesCtrParams aesCtrParams = format.getAesCtrKeyFormat().getParams();
        if (aesCtrParams.getIvSize() < MIN_AES_CTR_IV_SIZE_IN_BYTES
            || aesCtrParams.getIvSize() > 16) {
          throw new GeneralSecurityException("invalid AES STR IV size");
        }

        new HmacKeyManager().keyFactory().validateKeyFormat(format.getHmacKeyFormat());
        Validators.validateAesKeySize(format.getAesCtrKeyFormat().getKeySize());
      }

      @Override
      public AesCtrHmacAeadKeyFormat parseKeyFormat(ByteString byteString)
          throws InvalidProtocolBufferException {
        return AesCtrHmacAeadKeyFormat.parseFrom(
            byteString, ExtensionRegistryLite.getEmptyRegistry());
      }

      @Override
      public AesCtrHmacAeadKey createKey(AesCtrHmacAeadKeyFormat format)
          throws GeneralSecurityException {
        AesCtrKey aesCtrKey =
            AesCtrKey.newBuilder()
                .setParams(format.getAesCtrKeyFormat().getParams())
                .setKeyValue(
                    ByteString.copyFrom(Random.randBytes(format.getAesCtrKeyFormat().getKeySize())))
                .setVersion(getVersion())
                .build();
        HmacKey hmacKey = new HmacKeyManager().keyFactory().createKey(format.getHmacKeyFormat());
        return AesCtrHmacAeadKey.newBuilder()
            .setAesCtrKey(aesCtrKey)
            .setHmacKey(hmacKey)
            .setVersion(getVersion())
            .build();
      }
    };
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
    Registry.registerKeyManager(new AesCtrHmacAeadKeyManager(), newKeyAllowed);
    AesCtrHmacAeadProtoSerialization.register();
    MutablePrimitiveRegistry.globalInstance()
        .registerPrimitiveConstructor(AES_CTR_HMAC_AEAD_PRIMITIVE_CONSTRUCTOR);
    MutableParametersRegistry.globalInstance().putAll(namedParameters());
    MutableKeyDerivationRegistry.globalInstance().add(KEY_DERIVER, AesCtrHmacAeadParameters.class);
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

  @Override
  public TinkFipsUtil.AlgorithmFipsCompatibility fipsStatus() {
    return TinkFipsUtil.AlgorithmFipsCompatibility.ALGORITHM_REQUIRES_BORINGCRYPTO;
  };
}
