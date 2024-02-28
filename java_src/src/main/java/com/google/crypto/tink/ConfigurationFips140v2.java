// Copyright 2024 Google LLC
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

package com.google.crypto.tink;

import com.google.crypto.tink.aead.AeadWrapper;
import com.google.crypto.tink.aead.AesCtrHmacAeadKey;
import com.google.crypto.tink.aead.AesGcmKey;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.internal.InternalConfiguration;
import com.google.crypto.tink.internal.PrimitiveConstructor;
import com.google.crypto.tink.internal.PrimitiveRegistry;
import com.google.crypto.tink.internal.Random;
import com.google.crypto.tink.mac.ChunkedMac;
import com.google.crypto.tink.mac.ChunkedMacWrapper;
import com.google.crypto.tink.mac.HmacKey;
import com.google.crypto.tink.mac.MacWrapper;
import com.google.crypto.tink.mac.internal.ChunkedHmacImpl;
import com.google.crypto.tink.prf.HmacPrfKey;
import com.google.crypto.tink.prf.Prf;
import com.google.crypto.tink.prf.PrfSetWrapper;
import com.google.crypto.tink.signature.EcdsaPrivateKey;
import com.google.crypto.tink.signature.EcdsaPublicKey;
import com.google.crypto.tink.signature.PublicKeySignWrapper;
import com.google.crypto.tink.signature.PublicKeyVerifyWrapper;
import com.google.crypto.tink.signature.RsaSsaPkcs1PrivateKey;
import com.google.crypto.tink.signature.RsaSsaPkcs1PublicKey;
import com.google.crypto.tink.subtle.AesGcmJce;
import com.google.crypto.tink.subtle.EcdsaSignJce;
import com.google.crypto.tink.subtle.EcdsaVerifyJce;
import com.google.crypto.tink.subtle.EncryptThenAuthenticate;
import com.google.crypto.tink.subtle.PrfHmacJce;
import com.google.crypto.tink.subtle.PrfMac;
import com.google.crypto.tink.subtle.RsaSsaPkcs1SignJce;
import com.google.crypto.tink.subtle.RsaSsaPkcs1VerifyJce;
import java.security.GeneralSecurityException;

/** ConfigurationFips140v2 contains FIPS-compliant Tink primitives. */
public class ConfigurationFips140v2 {
  private ConfigurationFips140v2() {}

  /** get returns a Configuration containing Tink's FIPS-compliant primitives. */
  public static Configuration get() throws GeneralSecurityException {
    // First, check that we've got Conscrypt built with the BoringCrypto module.
    if (!TinkFipsUtil.fipsModuleAvailable()) {
      throw new GeneralSecurityException(
          "Conscrypt is not available or does not support checking for FIPS build.");
    }
    Random.validateUsesConscrypt();

    // Got Conscrypt, can proceed.
    PrimitiveRegistry.Builder builder = PrimitiveRegistry.builder();

    // Register Mac wrappers and concrete primitives.
    MacWrapper.registerToInternalPrimitiveRegistry(builder);
    ChunkedMacWrapper.registerToInternalPrimitiveRegistry(builder);
    builder.registerPrimitiveConstructor(
        PrimitiveConstructor.create(PrfMac::create, HmacKey.class, Mac.class));
    builder.registerPrimitiveConstructor(
        PrimitiveConstructor.create(ChunkedHmacImpl::new, HmacKey.class, ChunkedMac.class));

    // Register Aead wrapper and concrete primitives.
    AeadWrapper.registerToInternalPrimitiveRegistry(builder);
    builder.registerPrimitiveConstructor(
        PrimitiveConstructor.create(
            EncryptThenAuthenticate::create, AesCtrHmacAeadKey.class, Aead.class));
    builder.registerPrimitiveConstructor(
        PrimitiveConstructor.create(AesGcmJce::create, AesGcmKey.class, Aead.class));

    // Register Prf wrapper and concrete primitives.
    PrfSetWrapper.registerToInternalPrimitiveRegistry(builder);
    builder.registerPrimitiveConstructor(
        PrimitiveConstructor.create(PrfHmacJce::create, HmacPrfKey.class, Prf.class));

    // Register PublicKeySign/Verify wrapper and primitives.
    PublicKeySignWrapper.registerToInternalPrimitiveRegistry(builder);
    PublicKeyVerifyWrapper.registerToInternalPrimitiveRegistry(builder);
    builder.registerPrimitiveConstructor(
        PrimitiveConstructor.create(
            EcdsaSignJce::create, EcdsaPrivateKey.class, PublicKeySign.class));
    builder.registerPrimitiveConstructor(
        PrimitiveConstructor.create(
            EcdsaVerifyJce::create, EcdsaPublicKey.class, PublicKeyVerify.class));
    builder.registerPrimitiveConstructor(
        PrimitiveConstructor.create(
            ConfigurationFips140v2::rsaSsaPkcs1SignCreate,
            RsaSsaPkcs1PrivateKey.class,
            PublicKeySign.class));
    builder.registerPrimitiveConstructor(
        PrimitiveConstructor.create(
            ConfigurationFips140v2::rsaSsaPkcs1VerifyCreate,
            RsaSsaPkcs1PublicKey.class,
            PublicKeyVerify.class));

    return InternalConfiguration.createFromPrimitiveRegistry(builder.build());
  }

  // In FIPS only mode we additionally check if the modulus is 2048 or 3072, as this is the
  // only size which is covered by the FIPS validation and supported by Tink.
  // See
  // https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/3318
  private static PublicKeySign rsaSsaPkcs1SignCreate(RsaSsaPkcs1PrivateKey key)
      throws GeneralSecurityException {
    if (key.getParameters().getModulusSizeBits() != 2048
        && key.getParameters().getModulusSizeBits() != 3072) {
      throw new GeneralSecurityException(
          "Cannot create FIPS-compliant PublicKeySign: wrong RsaSsaPkcs1 key modulus size");
    }
    return RsaSsaPkcs1SignJce.create(key);
  }

  private static PublicKeyVerify rsaSsaPkcs1VerifyCreate(RsaSsaPkcs1PublicKey key)
      throws GeneralSecurityException {
    if (key.getParameters().getModulusSizeBits() != 2048
        && key.getParameters().getModulusSizeBits() != 3072) {
      throw new GeneralSecurityException(
          "Cannot create FIPS-compliant PublicKeyVerify: wrong RsaSsaPkcs1 key modulus size");
    }
    return RsaSsaPkcs1VerifyJce.create(key);
  }
}
