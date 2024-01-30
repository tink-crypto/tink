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
import com.google.crypto.tink.Registry;
import com.google.crypto.tink.SecretKeyAccess;
import com.google.crypto.tink.aead.internal.XChaCha20Poly1305Jce;
import com.google.crypto.tink.aead.internal.XChaCha20Poly1305ProtoSerialization;
import com.google.crypto.tink.internal.LegacyKeyManagerImpl;
import com.google.crypto.tink.internal.MutableKeyCreationRegistry;
import com.google.crypto.tink.internal.MutableKeyDerivationRegistry;
import com.google.crypto.tink.internal.MutableParametersRegistry;
import com.google.crypto.tink.internal.MutablePrimitiveRegistry;
import com.google.crypto.tink.internal.PrimitiveConstructor;
import com.google.crypto.tink.internal.Util;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.subtle.XChaCha20Poly1305;
import com.google.crypto.tink.util.SecretBytes;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import javax.annotation.Nullable;

/**
 * This instance of {@code KeyManager} generates new {@code XChaCha20Poly1305} keys and produces new
 * instances of {@code XChaCha20Poly1305}.
 */
public final class XChaCha20Poly1305KeyManager {

  private static Aead createAead(XChaCha20Poly1305Key key) throws GeneralSecurityException {
    if (XChaCha20Poly1305Jce.isSupported()) {
      return XChaCha20Poly1305Jce.create(key);
    }
    return XChaCha20Poly1305.create(key);
  }

  private static final PrimitiveConstructor<XChaCha20Poly1305Key, Aead>
      X_CHA_CHA_20_POLY_1305_PRIMITIVE_CONSTRUCTOR =
          PrimitiveConstructor.create(
              XChaCha20Poly1305KeyManager::createAead, XChaCha20Poly1305Key.class, Aead.class);

  private static final int KEY_SIZE_IN_BYTES = 32;

  static String getKeyType() {
    return "type.googleapis.com/google.crypto.tink.XChaCha20Poly1305Key";
  }

  private static final KeyManager<Aead> legacyKeyManager =
      LegacyKeyManagerImpl.create(
          getKeyType(),
          Aead.class,
          KeyMaterialType.SYMMETRIC,
          com.google.crypto.tink.proto.XChaCha20Poly1305Key.parser());

  @SuppressWarnings("InlineLambdaConstant") // We need a correct Object#equals in registration.
  private static final MutableKeyDerivationRegistry.InsecureKeyCreator<XChaCha20Poly1305Parameters>
      KEY_DERIVER = XChaCha20Poly1305KeyManager::createXChaChaKeyFromRandomness;

  @AccessesPartialKey
  static com.google.crypto.tink.aead.XChaCha20Poly1305Key createXChaChaKeyFromRandomness(
      XChaCha20Poly1305Parameters parameters,
      InputStream stream,
      @Nullable Integer idRequirement,
      SecretKeyAccess access)
      throws GeneralSecurityException {
    return com.google.crypto.tink.aead.XChaCha20Poly1305Key.create(
        parameters.getVariant(),
        Util.readIntoSecretBytes(stream, KEY_SIZE_IN_BYTES, access),
        idRequirement);
  }

  @SuppressWarnings("InlineLambdaConstant") // We need a correct Object#equals in registration.
  private static final MutableKeyCreationRegistry.KeyCreator<XChaCha20Poly1305Parameters>
      KEY_CREATOR = XChaCha20Poly1305KeyManager::createXChaChaKey;

  @AccessesPartialKey
  static com.google.crypto.tink.aead.XChaCha20Poly1305Key createXChaChaKey(
      XChaCha20Poly1305Parameters parameters, @Nullable Integer idRequirement)
      throws GeneralSecurityException {
    return com.google.crypto.tink.aead.XChaCha20Poly1305Key.create(
        parameters.getVariant(), SecretBytes.randomBytes(KEY_SIZE_IN_BYTES), idRequirement);
  }

  private static Map<String, Parameters> namedParameters() throws GeneralSecurityException {
    Map<String, Parameters> result = new HashMap<>();
        result.put(
            "XCHACHA20_POLY1305",
            XChaCha20Poly1305Parameters.create(XChaCha20Poly1305Parameters.Variant.TINK));
    result.put(
        "XCHACHA20_POLY1305_RAW",
        XChaCha20Poly1305Parameters.create(XChaCha20Poly1305Parameters.Variant.NO_PREFIX));
        return Collections.unmodifiableMap(result);
  }

  public static void register(boolean newKeyAllowed) throws GeneralSecurityException {
    XChaCha20Poly1305ProtoSerialization.register();
    MutablePrimitiveRegistry.globalInstance()
        .registerPrimitiveConstructor(X_CHA_CHA_20_POLY_1305_PRIMITIVE_CONSTRUCTOR);
    MutableParametersRegistry.globalInstance().putAll(namedParameters());
    MutableKeyCreationRegistry.globalInstance().add(KEY_CREATOR, XChaCha20Poly1305Parameters.class);
    MutableKeyDerivationRegistry.globalInstance()
        .add(KEY_DERIVER, XChaCha20Poly1305Parameters.class);
    Registry.registerKeyManager(legacyKeyManager, newKeyAllowed);
  }

  /**
   * @return a {@link KeyTemplate} that generates new instances of XChaCha20Poly1305 keys.
   */
  public static final KeyTemplate xChaCha20Poly1305Template() {
    return exceptionIsBug(
        () ->
            KeyTemplate.createFrom(
                XChaCha20Poly1305Parameters.create(XChaCha20Poly1305Parameters.Variant.TINK)));
  }

  /**
   * @return a {@link KeyTemplate} that generates new instances of XChaCha20Poly1305 keys. Keys
   *     generated from this template create ciphertexts compatible with libsodium and other
   *     libraries.
   */
  public static final KeyTemplate rawXChaCha20Poly1305Template() {
    return exceptionIsBug(
        () ->
            KeyTemplate.createFrom(
                XChaCha20Poly1305Parameters.create(XChaCha20Poly1305Parameters.Variant.NO_PREFIX)));
  }

  private XChaCha20Poly1305KeyManager() {}
}
