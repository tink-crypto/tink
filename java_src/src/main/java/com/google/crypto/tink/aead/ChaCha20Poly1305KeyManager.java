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
import com.google.crypto.tink.aead.internal.ChaCha20Poly1305Jce;
import com.google.crypto.tink.aead.internal.ChaCha20Poly1305ProtoSerialization;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.internal.KeyManagerRegistry;
import com.google.crypto.tink.internal.LegacyKeyManagerImpl;
import com.google.crypto.tink.internal.MutableKeyCreationRegistry;
import com.google.crypto.tink.internal.MutableParametersRegistry;
import com.google.crypto.tink.internal.MutablePrimitiveRegistry;
import com.google.crypto.tink.internal.PrimitiveConstructor;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.subtle.ChaCha20Poly1305;
import com.google.crypto.tink.util.SecretBytes;
import java.security.GeneralSecurityException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import javax.annotation.Nullable;

/**
 * This instance of {@code KeyManager} generates new {@code ChaCha20Poly1305} keys and produces new
 * instances of {@code ChaCha20Poly1305}.
 */
public final class ChaCha20Poly1305KeyManager {

  private static Aead createAead(ChaCha20Poly1305Key key) throws GeneralSecurityException {
    if (ChaCha20Poly1305Jce.isSupported()) {
      return ChaCha20Poly1305Jce.create(key);
    }
    return ChaCha20Poly1305.create(key);
  }

  private static final PrimitiveConstructor<ChaCha20Poly1305Key, Aead>
      CHA_CHA_20_POLY_1305_PRIMITIVE_CONSTRUCTOR =
          PrimitiveConstructor.create(
              ChaCha20Poly1305KeyManager::createAead, ChaCha20Poly1305Key.class, Aead.class);

  private static final int KEY_SIZE_IN_BYTES = 32;

  @SuppressWarnings("InlineLambdaConstant") // We need a correct Object#equals in registration.
  private static final MutableKeyCreationRegistry.KeyCreator<ChaCha20Poly1305Parameters>
      KEY_CREATOR = ChaCha20Poly1305KeyManager::createChaChaKey;

  private static final KeyManager<Aead> legacyKeyManager =
      LegacyKeyManagerImpl.create(
          getKeyType(),
          Aead.class,
          KeyMaterialType.SYMMETRIC,
          com.google.crypto.tink.proto.ChaCha20Poly1305Key.parser());

  @AccessesPartialKey
  static com.google.crypto.tink.aead.ChaCha20Poly1305Key createChaChaKey(
      ChaCha20Poly1305Parameters parameters, @Nullable Integer idRequirement)
      throws GeneralSecurityException {
    return com.google.crypto.tink.aead.ChaCha20Poly1305Key.create(
        parameters.getVariant(), SecretBytes.randomBytes(KEY_SIZE_IN_BYTES), idRequirement);
  }

  static String getKeyType() {
    return "type.googleapis.com/google.crypto.tink.ChaCha20Poly1305Key";
  }

  private static Map<String, Parameters> namedParameters() throws GeneralSecurityException {
        Map<String, Parameters> result = new HashMap<>();
        result.put(
            "CHACHA20_POLY1305",
            ChaCha20Poly1305Parameters.create(ChaCha20Poly1305Parameters.Variant.TINK));
        result.put(
            "CHACHA20_POLY1305_RAW",
            ChaCha20Poly1305Parameters.create(ChaCha20Poly1305Parameters.Variant.NO_PREFIX));
        return Collections.unmodifiableMap(result);
  }

  public static void register(boolean newKeyAllowed) throws GeneralSecurityException {
    if (!TinkFipsUtil.AlgorithmFipsCompatibility.ALGORITHM_NOT_FIPS.isCompatible()) {
      throw new GeneralSecurityException(
          "Registering ChaCha20Poly1305 is not supported in FIPS mode");
    }
    ChaCha20Poly1305ProtoSerialization.register();
    MutablePrimitiveRegistry.globalInstance()
        .registerPrimitiveConstructor(CHA_CHA_20_POLY_1305_PRIMITIVE_CONSTRUCTOR);
    MutableKeyCreationRegistry.globalInstance().add(KEY_CREATOR, ChaCha20Poly1305Parameters.class);
    MutableParametersRegistry.globalInstance().putAll(namedParameters());
    KeyManagerRegistry.globalInstance().registerKeyManager(legacyKeyManager, newKeyAllowed);
  }

  /**
   * @return a {@link KeyTemplate} that generates new instances of ChaCha20Poly1305 keys.
   */
  public static final KeyTemplate chaCha20Poly1305Template() {
    return exceptionIsBug(
        () ->
            KeyTemplate.createFrom(
                ChaCha20Poly1305Parameters.create(ChaCha20Poly1305Parameters.Variant.TINK)));
  }

  /**
   * @return a {@link KeyTemplate} that generates new instances of ChaCha20Poly1305 keys. Keys
   *     generated from this template create ciphertexts compatible with libsodium and other
   *     libraries.
   */
  public static final KeyTemplate rawChaCha20Poly1305Template() {
    return exceptionIsBug(
        () ->
            KeyTemplate.createFrom(
                ChaCha20Poly1305Parameters.create(ChaCha20Poly1305Parameters.Variant.NO_PREFIX)));
  }

  private ChaCha20Poly1305KeyManager() {}
}
