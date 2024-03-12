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

package com.google.crypto.tink.signature;

import static com.google.crypto.tink.internal.TinkBugException.exceptionIsBug;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.KeyManager;
import com.google.crypto.tink.KeyTemplate;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.PrivateKeyManager;
import com.google.crypto.tink.PublicKeySign;
import com.google.crypto.tink.PublicKeyVerify;
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
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.signature.internal.Ed25519ProtoSerialization;
import com.google.crypto.tink.subtle.Ed25519Sign;
import com.google.crypto.tink.subtle.Ed25519Verify;
import com.google.crypto.tink.util.Bytes;
import com.google.crypto.tink.util.SecretBytes;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import javax.annotation.Nullable;

/**
 * This instance of {@code KeyManager} generates new {@code Ed25519PrivateKey} keys and produces new
 * instances of {@code Ed25519Sign}.
 */
public final class Ed25519PrivateKeyManager {
  private static final PrimitiveConstructor<Ed25519PrivateKey, PublicKeySign>
      PUBLIC_KEY_SIGN_PRIMITIVE_CONSTRUCTOR =
          PrimitiveConstructor.create(
              Ed25519Sign::create, Ed25519PrivateKey.class, PublicKeySign.class);

  private static final PrimitiveConstructor<Ed25519PublicKey, PublicKeyVerify>
      PUBLIC_KEY_VERIFY_PRIMITIVE_CONSTRUCTOR =
          PrimitiveConstructor.create(
              Ed25519Verify::create, Ed25519PublicKey.class, PublicKeyVerify.class);

  private static final PrivateKeyManager<PublicKeySign> legacyPrivateKeyManager =
      LegacyKeyManagerImpl.createPrivateKeyManager(
          getKeyType(),
          PublicKeySign.class,
          com.google.crypto.tink.proto.Ed25519PrivateKey.parser());

  private static final KeyManager<PublicKeyVerify> legacyPublicKeyManager =
      LegacyKeyManagerImpl.create(
          Ed25519PublicKeyManager.getKeyType(),
          PublicKeyVerify.class,
          KeyMaterialType.ASYMMETRIC_PUBLIC,
          com.google.crypto.tink.proto.Ed25519PublicKey.parser());

  static String getKeyType() {
    return "type.googleapis.com/google.crypto.tink.Ed25519PrivateKey";
  }

  @AccessesPartialKey
  static com.google.crypto.tink.signature.Ed25519PrivateKey createEd25519KeyFromRandomness(
      Ed25519Parameters parameters,
      InputStream stream,
      @Nullable Integer idRequirement,
      SecretKeyAccess access)
      throws GeneralSecurityException {
    SecretBytes pseudorandomness =
        Util.readIntoSecretBytes(stream, Ed25519Sign.SECRET_KEY_LEN, access);
    Ed25519Sign.KeyPair keyPair =
        Ed25519Sign.KeyPair.newKeyPairFromSeed(pseudorandomness.toByteArray(access));
    com.google.crypto.tink.signature.Ed25519PublicKey publicKey =
        com.google.crypto.tink.signature.Ed25519PublicKey.create(
            parameters.getVariant(), Bytes.copyFrom(keyPair.getPublicKey()), idRequirement);
    return com.google.crypto.tink.signature.Ed25519PrivateKey.create(
        publicKey, SecretBytes.copyFrom(keyPair.getPrivateKey(), access));
  }

  @SuppressWarnings("InlineLambdaConstant") // We need a correct Object#equals in registration.
  private static final MutableKeyDerivationRegistry.InsecureKeyCreator<Ed25519Parameters>
      KEY_DERIVER = Ed25519PrivateKeyManager::createEd25519KeyFromRandomness;

  @AccessesPartialKey
  static com.google.crypto.tink.signature.Ed25519PrivateKey createEd25519Key(
      Ed25519Parameters parameters, @Nullable Integer idRequirement)
      throws GeneralSecurityException {
    Ed25519Sign.KeyPair keyPair = Ed25519Sign.KeyPair.newKeyPair();
    com.google.crypto.tink.signature.Ed25519PublicKey publicKey =
        com.google.crypto.tink.signature.Ed25519PublicKey.create(
            parameters.getVariant(), Bytes.copyFrom(keyPair.getPublicKey()), idRequirement);
    return com.google.crypto.tink.signature.Ed25519PrivateKey.create(
        publicKey, SecretBytes.copyFrom(keyPair.getPrivateKey(), InsecureSecretKeyAccess.get()));
  }

  @SuppressWarnings("InlineLambdaConstant") // We need a correct Object#equals in registration.
  private static final MutableKeyCreationRegistry.KeyCreator<Ed25519Parameters> KEY_CREATOR =
      Ed25519PrivateKeyManager::createEd25519Key;

  private static Map<String, Parameters> namedParameters() throws GeneralSecurityException {
        Map<String, Parameters> result = new HashMap<>();
        result.put("ED25519", Ed25519Parameters.create(Ed25519Parameters.Variant.TINK));
        result.put("ED25519_RAW", Ed25519Parameters.create(Ed25519Parameters.Variant.NO_PREFIX));
        // This is identical to ED25519_RAW.
        // It is needed to maintain backward compatibility with SignatureKeyTemplates.
        result.put(
            "ED25519WithRawOutput", Ed25519Parameters.create(Ed25519Parameters.Variant.NO_PREFIX));
        return Collections.unmodifiableMap(result);
  }

  /**
   * Registers the {@link Ed25519PrivateKeyManager} and the {@link Ed25519PublicKeyManager} with the
   * registry, so that the the Ed25519-Keys can be used with Tink.
   */
  public static void registerPair(boolean newKeyAllowed) throws GeneralSecurityException {
    if (!TinkFipsUtil.AlgorithmFipsCompatibility.ALGORITHM_NOT_FIPS.isCompatible()) {
      throw new GeneralSecurityException("Registering AES GCM SIV is not supported in FIPS mode");
    }
    Ed25519ProtoSerialization.register();
    MutableParametersRegistry.globalInstance().putAll(namedParameters());
    MutableKeyCreationRegistry.globalInstance().add(KEY_CREATOR, Ed25519Parameters.class);
    MutableKeyDerivationRegistry.globalInstance().add(KEY_DERIVER, Ed25519Parameters.class);
    MutablePrimitiveRegistry.globalInstance()
        .registerPrimitiveConstructor(PUBLIC_KEY_SIGN_PRIMITIVE_CONSTRUCTOR);
    MutablePrimitiveRegistry.globalInstance()
        .registerPrimitiveConstructor(PUBLIC_KEY_VERIFY_PRIMITIVE_CONSTRUCTOR);
    KeyManagerRegistry.globalInstance().registerKeyManager(legacyPrivateKeyManager, newKeyAllowed);
    KeyManagerRegistry.globalInstance()
        .registerKeyManager(legacyPublicKeyManager, /* newKeyAllowed= */ false);
  }

  /**
   * @return A {@link KeyTemplate} that generates new instances of ED25519 keys.
   */
  public static final KeyTemplate ed25519Template() {
    return exceptionIsBug(
        () -> KeyTemplate.createFrom(Ed25519Parameters.create(Ed25519Parameters.Variant.TINK)));
  }

  /**
   * @return A {@link KeyTemplate} that generates new instances of Ed25519 keys. Keys generated from
   *     this template creates raw signatures of exactly 64 bytes. It's compatible with most other
   *     libraries.
   */
  public static final KeyTemplate rawEd25519Template() {
    return exceptionIsBug(
        () ->
            KeyTemplate.createFrom(Ed25519Parameters.create(Ed25519Parameters.Variant.NO_PREFIX)));
  }

  private Ed25519PrivateKeyManager() {}
}
