// Copyright 2017 Google LLC
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

package com.google.crypto.tink.mac;

import static com.google.crypto.tink.internal.TinkBugException.exceptionIsBug;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.KeyManager;
import com.google.crypto.tink.KeyTemplate;
import com.google.crypto.tink.Mac;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.SecretKeyAccess;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.internal.KeyManagerRegistry;
import com.google.crypto.tink.internal.LegacyKeyManagerImpl;
import com.google.crypto.tink.internal.MutableKeyCreationRegistry;
import com.google.crypto.tink.internal.MutableKeyDerivationRegistry;
import com.google.crypto.tink.internal.MutableParametersRegistry;
import com.google.crypto.tink.internal.MutablePrimitiveRegistry;
import com.google.crypto.tink.internal.PrimitiveConstructor;
import com.google.crypto.tink.internal.Util;
import com.google.crypto.tink.mac.internal.ChunkedHmacImpl;
import com.google.crypto.tink.mac.internal.HmacProtoSerialization;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.subtle.PrfMac;
import com.google.crypto.tink.util.SecretBytes;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import javax.annotation.Nullable;

/**
 * This key manager generates new {@code HmacKey} keys and produces new instances of {@code
 * PrfHmacJce}.
 */
public final class HmacKeyManager {
  private static final PrimitiveConstructor<HmacKey, ChunkedMac> CHUNKED_MAC_PRIMITIVE_CONSTRUCTOR =
      PrimitiveConstructor.create(ChunkedHmacImpl::new, HmacKey.class, ChunkedMac.class);
  private static final PrimitiveConstructor<HmacKey, Mac> MAC_PRIMITIVE_CONSTRUCTOR =
      PrimitiveConstructor.create(PrfMac::create, HmacKey.class, Mac.class);

  private static final KeyManager<Mac> legacyKeyManager =
      LegacyKeyManagerImpl.create(
          "type.googleapis.com/google.crypto.tink.HmacKey",
          Mac.class,
          KeyMaterialType.SYMMETRIC,
          com.google.crypto.tink.proto.HmacKey.parser());

  static String getKeyType() {
    return "type.googleapis.com/google.crypto.tink.HmacKey";
  }


  @SuppressWarnings("InlineLambdaConstant") // We need a correct Object#equals in registration.
  private static final MutableKeyDerivationRegistry.InsecureKeyCreator<HmacParameters> KEY_DERIVER =
      HmacKeyManager::createHmacKeyFromRandomness;

  @AccessesPartialKey
  static HmacKey createHmacKeyFromRandomness(
      HmacParameters parameters,
      InputStream stream,
      @Nullable Integer idRequirement,
      SecretKeyAccess access)
      throws GeneralSecurityException {
    return HmacKey.builder()
        .setParameters(parameters)
        .setKeyBytes(Util.readIntoSecretBytes(stream, parameters.getKeySizeBytes(), access))
        .setIdRequirement(idRequirement)
        .build();
  }

  @SuppressWarnings("InlineLambdaConstant") // We need a correct Object#equals in registration.
  private static final MutableKeyCreationRegistry.KeyCreator<HmacParameters> KEY_CREATOR =
      HmacKeyManager::createNewHmacKey;

  @AccessesPartialKey
  static HmacKey createNewHmacKey(HmacParameters parameters, @Nullable Integer idRequirement)
      throws GeneralSecurityException {
    return HmacKey.builder()
        .setParameters(parameters)
        .setKeyBytes(SecretBytes.randomBytes(parameters.getKeySizeBytes()))
        .setIdRequirement(idRequirement)
        .build();
  }

  private static Map<String, Parameters> namedParameters() throws GeneralSecurityException {
        Map<String, Parameters> result = new HashMap<>();
        result.put("HMAC_SHA256_128BITTAG", PredefinedMacParameters.HMAC_SHA256_128BITTAG);
        result.put(
            "HMAC_SHA256_128BITTAG_RAW",
            HmacParameters.builder()
                .setKeySizeBytes(32)
                .setTagSizeBytes(16)
                .setVariant(HmacParameters.Variant.NO_PREFIX)
                .setHashType(HmacParameters.HashType.SHA256)
                .build());
        result.put(
            "HMAC_SHA256_256BITTAG",
            HmacParameters.builder()
                .setKeySizeBytes(32)
                .setTagSizeBytes(32)
                .setVariant(HmacParameters.Variant.TINK)
                .setHashType(HmacParameters.HashType.SHA256)
                .build());
        result.put(
            "HMAC_SHA256_256BITTAG_RAW",
            HmacParameters.builder()
                .setKeySizeBytes(32)
                .setTagSizeBytes(32)
                .setVariant(HmacParameters.Variant.NO_PREFIX)
                .setHashType(HmacParameters.HashType.SHA256)
                .build());
        result.put(
            "HMAC_SHA512_128BITTAG",
            HmacParameters.builder()
                .setKeySizeBytes(64)
                .setTagSizeBytes(16)
                .setVariant(HmacParameters.Variant.TINK)
                .setHashType(HmacParameters.HashType.SHA512)
                .build());
        result.put(
            "HMAC_SHA512_128BITTAG_RAW",
            HmacParameters.builder()
                .setKeySizeBytes(64)
                .setTagSizeBytes(16)
                .setVariant(HmacParameters.Variant.NO_PREFIX)
                .setHashType(HmacParameters.HashType.SHA512)
                .build());
        result.put(
            "HMAC_SHA512_256BITTAG",
            HmacParameters.builder()
                .setKeySizeBytes(64)
                .setTagSizeBytes(32)
                .setVariant(HmacParameters.Variant.TINK)
                .setHashType(HmacParameters.HashType.SHA512)
                .build());
        result.put(
            "HMAC_SHA512_256BITTAG_RAW",
            HmacParameters.builder()
                .setKeySizeBytes(64)
                .setTagSizeBytes(32)
                .setVariant(HmacParameters.Variant.NO_PREFIX)
                .setHashType(HmacParameters.HashType.SHA512)
                .build());
        result.put("HMAC_SHA512_512BITTAG", PredefinedMacParameters.HMAC_SHA512_512BITTAG);
        result.put(
            "HMAC_SHA512_512BITTAG_RAW",
            HmacParameters.builder()
                .setKeySizeBytes(64)
                .setTagSizeBytes(64)
                .setVariant(HmacParameters.Variant.NO_PREFIX)
                .setHashType(HmacParameters.HashType.SHA512)
                .build());
        return Collections.unmodifiableMap(result);
  }

  private static final TinkFipsUtil.AlgorithmFipsCompatibility FIPS =
      TinkFipsUtil.AlgorithmFipsCompatibility.ALGORITHM_REQUIRES_BORINGCRYPTO;

  public static void register(boolean newKeyAllowed) throws GeneralSecurityException {
    if (!FIPS.isCompatible()) {
      throw new GeneralSecurityException(
          "Can not use HMAC in FIPS-mode, as BoringCrypto module is not available.");
    }
    HmacProtoSerialization.register();
    MutablePrimitiveRegistry.globalInstance()
        .registerPrimitiveConstructor(CHUNKED_MAC_PRIMITIVE_CONSTRUCTOR);
    MutablePrimitiveRegistry.globalInstance()
        .registerPrimitiveConstructor(MAC_PRIMITIVE_CONSTRUCTOR);
    MutableParametersRegistry.globalInstance().putAll(namedParameters());
    MutableKeyCreationRegistry.globalInstance().add(KEY_CREATOR, HmacParameters.class);
    MutableKeyDerivationRegistry.globalInstance().add(KEY_DERIVER, HmacParameters.class);
    KeyManagerRegistry.globalInstance()
        .registerKeyManagerWithFipsCompatibility(legacyKeyManager, FIPS, newKeyAllowed);
  }

  /**
   * @return A {@link KeyTemplate} that generates new instances of HMAC keys with the following
   *     parameters:
   *     <ul>
   *       <li>Key size: 32 bytes
   *       <li>Tag size: 16 bytes
   *       <li>Hash function: SHA256
   *       <li>Prefix type: {@link KeyTemplate.OutputPrefixType#TINK}
   *     </ul>
   */
  public static final KeyTemplate hmacSha256HalfDigestTemplate() {
    return exceptionIsBug(
        () ->
            KeyTemplate.createFrom(
                HmacParameters.builder()
                    .setKeySizeBytes(32)
                    .setTagSizeBytes(16)
                    .setHashType(HmacParameters.HashType.SHA256)
                    .setVariant(HmacParameters.Variant.TINK)
                    .build()));
  }

  /**
   * @return A {@link KeyTemplate} that generates new instances of HMAC keys with the following
   *     parameters:
   *     <ul>
   *       <li>Key size: 32 bytes
   *       <li>Tag size: 32 bytes
   *       <li>Hash function: SHA256
   *       <li>Prefix type: {@link KeyTemplate.OutputPrefixType#TINK}
   *     </ul>
   */
  public static final KeyTemplate hmacSha256Template() {
    return exceptionIsBug(
        () ->
            KeyTemplate.createFrom(
                HmacParameters.builder()
                    .setKeySizeBytes(32)
                    .setTagSizeBytes(32)
                    .setHashType(HmacParameters.HashType.SHA256)
                    .setVariant(HmacParameters.Variant.TINK)
                    .build()));
  }

  /**
   * @return A {@link KeyTemplate} that generates new instances of HMAC keys with the following
   *     parameters:
   *     <ul>
   *       <li>Key size: 64 bytes
   *       <li>Tag size: 32 bytes
   *       <li>Hash function: SHA512
   *       <li>Prefix type: {@link KeyTemplate.OutputPrefixType#TINK}
   *     </ul>
   */
  public static final KeyTemplate hmacSha512HalfDigestTemplate() {
    return exceptionIsBug(
        () ->
            KeyTemplate.createFrom(
                HmacParameters.builder()
                    .setKeySizeBytes(64)
                    .setTagSizeBytes(32)
                    .setHashType(HmacParameters.HashType.SHA512)
                    .setVariant(HmacParameters.Variant.TINK)
                    .build()));
  }

  /**
   * @return A {@link KeyTemplate} that generates new instances of HMAC keys with the following
   *     parameters:
   *     <ul>
   *       <li>Key size: 64 bytes
   *       <li>Tag size: 64 bytes
   *       <li>Hash function: SHA512
   *       <li>Prefix type: {@link KeyTemplate.OutputPrefixType#TINK}
   *     </ul>
   */
  public static final KeyTemplate hmacSha512Template() {
    return exceptionIsBug(
        () ->
            KeyTemplate.createFrom(
                HmacParameters.builder()
                    .setKeySizeBytes(64)
                    .setTagSizeBytes(64)
                    .setHashType(HmacParameters.HashType.SHA512)
                    .setVariant(HmacParameters.Variant.TINK)
                    .build()));
  }

  private HmacKeyManager() {}
}
