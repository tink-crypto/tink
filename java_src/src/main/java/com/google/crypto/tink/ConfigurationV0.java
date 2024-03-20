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
import com.google.crypto.tink.aead.AesEaxKey;
import com.google.crypto.tink.aead.AesGcmKey;
import com.google.crypto.tink.aead.AesGcmSivKey;
import com.google.crypto.tink.aead.ChaCha20Poly1305Key;
import com.google.crypto.tink.aead.XChaCha20Poly1305Key;
import com.google.crypto.tink.aead.internal.ChaCha20Poly1305Jce;
import com.google.crypto.tink.aead.internal.XChaCha20Poly1305Jce;
import com.google.crypto.tink.aead.subtle.AesGcmSiv;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.daead.AesSivKey;
import com.google.crypto.tink.daead.DeterministicAeadWrapper;
import com.google.crypto.tink.hybrid.EciesPrivateKey;
import com.google.crypto.tink.hybrid.EciesPublicKey;
import com.google.crypto.tink.hybrid.HpkePrivateKey;
import com.google.crypto.tink.hybrid.HpkePublicKey;
import com.google.crypto.tink.hybrid.HybridDecryptWrapper;
import com.google.crypto.tink.hybrid.HybridEncryptWrapper;
import com.google.crypto.tink.hybrid.internal.HpkeDecrypt;
import com.google.crypto.tink.hybrid.internal.HpkeEncrypt;
import com.google.crypto.tink.internal.InternalConfiguration;
import com.google.crypto.tink.internal.PrimitiveConstructor;
import com.google.crypto.tink.internal.PrimitiveRegistry;
import com.google.crypto.tink.mac.AesCmacKey;
import com.google.crypto.tink.mac.ChunkedMac;
import com.google.crypto.tink.mac.ChunkedMacWrapper;
import com.google.crypto.tink.mac.HmacKey;
import com.google.crypto.tink.mac.MacWrapper;
import com.google.crypto.tink.mac.internal.ChunkedAesCmacImpl;
import com.google.crypto.tink.mac.internal.ChunkedHmacImpl;
import com.google.crypto.tink.prf.AesCmacPrfKey;
import com.google.crypto.tink.prf.HkdfPrfKey;
import com.google.crypto.tink.prf.HkdfPrfParameters;
import com.google.crypto.tink.prf.HmacPrfKey;
import com.google.crypto.tink.prf.Prf;
import com.google.crypto.tink.prf.PrfSetWrapper;
import com.google.crypto.tink.signature.EcdsaPrivateKey;
import com.google.crypto.tink.signature.EcdsaPublicKey;
import com.google.crypto.tink.signature.Ed25519PrivateKey;
import com.google.crypto.tink.signature.Ed25519PublicKey;
import com.google.crypto.tink.signature.PublicKeySignWrapper;
import com.google.crypto.tink.signature.PublicKeyVerifyWrapper;
import com.google.crypto.tink.signature.RsaSsaPkcs1PrivateKey;
import com.google.crypto.tink.signature.RsaSsaPkcs1PublicKey;
import com.google.crypto.tink.signature.RsaSsaPssPrivateKey;
import com.google.crypto.tink.signature.RsaSsaPssPublicKey;
import com.google.crypto.tink.streamingaead.AesCtrHmacStreamingKey;
import com.google.crypto.tink.streamingaead.AesGcmHkdfStreamingKey;
import com.google.crypto.tink.streamingaead.StreamingAeadWrapper;
import com.google.crypto.tink.subtle.AesCtrHmacStreaming;
import com.google.crypto.tink.subtle.AesEaxJce;
import com.google.crypto.tink.subtle.AesGcmHkdfStreaming;
import com.google.crypto.tink.subtle.AesGcmJce;
import com.google.crypto.tink.subtle.AesSiv;
import com.google.crypto.tink.subtle.ChaCha20Poly1305;
import com.google.crypto.tink.subtle.EcdsaSignJce;
import com.google.crypto.tink.subtle.EcdsaVerifyJce;
import com.google.crypto.tink.subtle.EciesAeadHkdfHybridDecrypt;
import com.google.crypto.tink.subtle.EciesAeadHkdfHybridEncrypt;
import com.google.crypto.tink.subtle.Ed25519Sign;
import com.google.crypto.tink.subtle.Ed25519Verify;
import com.google.crypto.tink.subtle.EncryptThenAuthenticate;
import com.google.crypto.tink.subtle.PrfAesCmac;
import com.google.crypto.tink.subtle.PrfHmacJce;
import com.google.crypto.tink.subtle.PrfMac;
import com.google.crypto.tink.subtle.RsaSsaPkcs1SignJce;
import com.google.crypto.tink.subtle.RsaSsaPkcs1VerifyJce;
import com.google.crypto.tink.subtle.RsaSsaPssSignJce;
import com.google.crypto.tink.subtle.RsaSsaPssVerifyJce;
import com.google.crypto.tink.subtle.XChaCha20Poly1305;
import com.google.crypto.tink.subtle.prf.HkdfStreamingPrf;
import com.google.crypto.tink.subtle.prf.PrfImpl;
import java.security.GeneralSecurityException;

/**
 * ConfigurationV0 contains the following primitives and algorithms:
 *
 * <p>MAC/ChunkedMAC:
 * <ul>
 *   <li>AesCmac</li>
 *   <li>Hmac</li>
 * </ul>
 *
 * <p>AEAD:
 * <ul>
 *   <li>AesCtrHmac</li>
 *   <li>AesEax</li>
 *   <li>AesGcm</li>
 *   <li>AesGcmSiv</li>
 *   <li>ChaCha20Poly1305</li>
 *   <li>XChaCha20Poly1305</li>
 * </ul>
 *
 * <p>DAEAD:
 * <ul>
 *   <li>AesSiv</li>
 * </ul>
 *
 * <p>StreamingAEAD:
 * <ul>
 *   <li>AesCtrHmac</li>
 *   <li>AesGcmHkdf</li>
 * </ul>
 *
 * <p>Hybrid:
 * <ul>
 *   <li>Ecies</li>
 *   <li>Hpke</li>
 * </ul>
 *
 * <p>PRF:
 * <ul>
 *   <li>AesCmac</li>
 *   <li>Hkdf</li>
 *   <li>Hmac</li>
 * </ul>
 *
 * <p>Signatures:
 * <ul>
 *   <li>Ed25519</li>
 *   <li>Esdsa</li>
 *   <li>RsaSsaPkcs1</li>
 *   <li>RsaSsaPss</li>
 * </ul>
 */
// TODO(b/265864709): add cross-language tests for this class.
public class ConfigurationV0 {
  private ConfigurationV0() {}

  public static Configuration get() throws GeneralSecurityException {
    if (TinkFipsUtil.useOnlyFips()) {
      throw new GeneralSecurityException(
          "Cannot use non-FIPS-compliant ConfigurationV0 in FIPS mode");
    }

    PrimitiveRegistry.Builder builder = PrimitiveRegistry.builder();

    // Register Mac wrappers and concrete primitives.
    MacWrapper.registerToInternalPrimitiveRegistry(builder);
    ChunkedMacWrapper.registerToInternalPrimitiveRegistry(builder);
    builder.registerPrimitiveConstructor(
        PrimitiveConstructor.create(ConfigurationV0::createAesCmac, AesCmacKey.class, Mac.class));
    builder.registerPrimitiveConstructor(
        PrimitiveConstructor.create(PrfMac::create, HmacKey.class, Mac.class));
    builder.registerPrimitiveConstructor(
        PrimitiveConstructor.create(
            ConfigurationV0::createChunkedAesCmac, AesCmacKey.class, ChunkedMac.class));
    builder.registerPrimitiveConstructor(
        PrimitiveConstructor.create(ChunkedHmacImpl::new, HmacKey.class, ChunkedMac.class));

    // Register Aead wrapper and concrete primitives.
    AeadWrapper.registerToInternalPrimitiveRegistry(builder);
    builder.registerPrimitiveConstructor(
        PrimitiveConstructor.create(
            EncryptThenAuthenticate::create, AesCtrHmacAeadKey.class, Aead.class));
    builder.registerPrimitiveConstructor(
        PrimitiveConstructor.create(AesEaxJce::create, AesEaxKey.class, Aead.class));
    builder.registerPrimitiveConstructor(
        PrimitiveConstructor.create(AesGcmJce::create, AesGcmKey.class, Aead.class));
    builder.registerPrimitiveConstructor(
        PrimitiveConstructor.create(AesGcmSiv::create, AesGcmSivKey.class, Aead.class));
    builder.registerPrimitiveConstructor(
        PrimitiveConstructor.create(
            ConfigurationV0::createChaCha20Poly1305, ChaCha20Poly1305Key.class, Aead.class));
    builder.registerPrimitiveConstructor(
        PrimitiveConstructor.create(
            ConfigurationV0::createXChaCha20Poly1305, XChaCha20Poly1305Key.class, Aead.class));

    // Register DeterministicAead wrapper and concrete primitives.
    DeterministicAeadWrapper.registerToInternalPrimitiveRegistry(builder);
    builder.registerPrimitiveConstructor(
        PrimitiveConstructor.create(
            ConfigurationV0::createAesSiv, AesSivKey.class, DeterministicAead.class));

    // Register StreamingAead wrapper and concrete primitives.
    StreamingAeadWrapper.registerToInternalPrimitiveRegistry(builder);
    builder.registerPrimitiveConstructor(
        PrimitiveConstructor.create(
            AesCtrHmacStreaming::create, AesCtrHmacStreamingKey.class, StreamingAead.class));
    builder.registerPrimitiveConstructor(
        PrimitiveConstructor.create(
            AesGcmHkdfStreaming::create, AesGcmHkdfStreamingKey.class, StreamingAead.class));

    // Register HybridEncrypt/Decrypt wrapper and concrete primitives.
    HybridEncryptWrapper.registerToInternalPrimitiveRegistry(builder);
    HybridDecryptWrapper.registerToInternalPrimitiveRegistry(builder);
    builder.registerPrimitiveConstructor(
        PrimitiveConstructor.create(
            EciesAeadHkdfHybridEncrypt::create, EciesPublicKey.class, HybridEncrypt.class));
    builder.registerPrimitiveConstructor(
        PrimitiveConstructor.create(
            EciesAeadHkdfHybridDecrypt::create, EciesPrivateKey.class, HybridDecrypt.class));
    builder.registerPrimitiveConstructor(
        PrimitiveConstructor.create(HpkeEncrypt::create, HpkePublicKey.class, HybridEncrypt.class));
    builder.registerPrimitiveConstructor(
        PrimitiveConstructor.create(
            HpkeDecrypt::create, HpkePrivateKey.class, HybridDecrypt.class));

    // Register Prf wrapper and concrete primitives.
    PrfSetWrapper.registerToInternalPrimitiveRegistry(builder);
    builder.registerPrimitiveConstructor(
        PrimitiveConstructor.create(
            ConfigurationV0::createAesCmacPrf, AesCmacPrfKey.class, Prf.class));
    builder.registerPrimitiveConstructor(
        PrimitiveConstructor.create(ConfigurationV0::createHkdfPrf, HkdfPrfKey.class, Prf.class));
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
            Ed25519Sign::create, Ed25519PrivateKey.class, PublicKeySign.class));
    builder.registerPrimitiveConstructor(
        PrimitiveConstructor.create(
            Ed25519Verify::create, Ed25519PublicKey.class, PublicKeyVerify.class));
    builder.registerPrimitiveConstructor(
        PrimitiveConstructor.create(
            RsaSsaPkcs1SignJce::create, RsaSsaPkcs1PrivateKey.class, PublicKeySign.class));
    builder.registerPrimitiveConstructor(
        PrimitiveConstructor.create(
            RsaSsaPkcs1VerifyJce::create, RsaSsaPkcs1PublicKey.class, PublicKeyVerify.class));
    builder.registerPrimitiveConstructor(
        PrimitiveConstructor.create(
            RsaSsaPssSignJce::create, RsaSsaPssPrivateKey.class, PublicKeySign.class));
    builder.registerPrimitiveConstructor(
        PrimitiveConstructor.create(
            RsaSsaPssVerifyJce::create, RsaSsaPssPublicKey.class, PublicKeyVerify.class));

    return InternalConfiguration.createFromPrimitiveRegistry(builder.build());
  }

  // For compatibility reasons, and on some versions of Android for correctness reasons,
  // we do not remove our implementation of ChaCha20Poly1305, and fall back to it in cases
  // where we cannot use the JCE implementation.
  private static Aead createChaCha20Poly1305(ChaCha20Poly1305Key key)
      throws GeneralSecurityException {
    if (ChaCha20Poly1305Jce.isSupported()) {
      return ChaCha20Poly1305Jce.create(key);
    }
    return ChaCha20Poly1305.create(key);
  }

  // For compatibility reasons, and on some versions of Android for correctness reasons,
  // we do not remove our implementation of XChaCha20Poly1305, and fall back to it in cases
  // where we cannot use the JCE implementation.
  private static Aead createXChaCha20Poly1305(XChaCha20Poly1305Key key)
      throws GeneralSecurityException {
    if (XChaCha20Poly1305Jce.isSupported()) {
      return XChaCha20Poly1305Jce.create(key);
    }
    return XChaCha20Poly1305.create(key);
  }

  private static DeterministicAead createAesSiv(AesSivKey key) throws GeneralSecurityException {
    int aesSivKeySizeInBytes = 64;
    if (key.getParameters().getKeySizeBytes() != aesSivKeySizeInBytes) {
      throw new GeneralSecurityException(
          "invalid key size: "
              + key.getParameters().getKeySizeBytes()
              + ". Valid keys must have "
              + aesSivKeySizeInBytes
              + " bytes.");
    }
    return AesSiv.create(key);
  }

  private static Prf createHkdfPrf(HkdfPrfKey key) throws GeneralSecurityException {
    // We use a somewhat larger minimum key size than usual, because PRFs might be used by many
    // users,
    // in which case the security can degrade by a factor depending on the number of users.
    // (Discussed
    // for example in https://eprint.iacr.org/2012/159)
    int minHkdfPrfKeySize = 32;
    if (key.getParameters().getKeySizeBytes() < minHkdfPrfKeySize) {
      throw new GeneralSecurityException("Key size must be at least " + minHkdfPrfKeySize);
    }
    if (key.getParameters().getHashType() != HkdfPrfParameters.HashType.SHA256
        && key.getParameters().getHashType() != HkdfPrfParameters.HashType.SHA512) {
      throw new GeneralSecurityException("Hash type must be SHA256 or SHA512");
    }
    return PrfImpl.wrap(HkdfStreamingPrf.create(key));
  }

  // We only allow 32-byte AesCmac keys.
  private static final int AES_CMAC_KEY_SIZE_BYTES = 32;

  private static Prf createAesCmacPrf(AesCmacPrfKey key) throws GeneralSecurityException {
    if (key.getParameters().getKeySizeBytes() != AES_CMAC_KEY_SIZE_BYTES) {
      throw new GeneralSecurityException("Key size must be 32 bytes");
    }
    return PrfAesCmac.create(key);
  }

  private static ChunkedMac createChunkedAesCmac(AesCmacKey key) throws GeneralSecurityException {
    if (key.getParameters().getKeySizeBytes() != AES_CMAC_KEY_SIZE_BYTES) {
      throw new GeneralSecurityException("AesCmac key size is not 32 bytes");
    }
    return new ChunkedAesCmacImpl(key);
  }

  private static Mac createAesCmac(AesCmacKey key) throws GeneralSecurityException {
    if (key.getParameters().getKeySizeBytes() != AES_CMAC_KEY_SIZE_BYTES) {
      throw new GeneralSecurityException("AesCmac key size is not 32 bytes");
    }
    return PrfMac.create(key);
  }
}
