// Copyright 2021 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
///////////////////////////////////////////////////////////////////////////////

package com.google.crypto.tink.hybrid.internal;

import com.google.crypto.tink.HybridDecrypt;
import com.google.crypto.tink.KeyTemplate;
import com.google.crypto.tink.KeyTypeManager;
import com.google.crypto.tink.PrivateKeyTypeManager;
import com.google.crypto.tink.Registry;
import com.google.crypto.tink.proto.HpkeAead;
import com.google.crypto.tink.proto.HpkeKdf;
import com.google.crypto.tink.proto.HpkeKem;
import com.google.crypto.tink.proto.HpkeKeyFormat;
import com.google.crypto.tink.proto.HpkeParams;
import com.google.crypto.tink.proto.HpkePrivateKey;
import com.google.crypto.tink.proto.HpkePublicKey;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.subtle.Validators;
import com.google.crypto.tink.subtle.X25519;
import com.google.protobuf.ByteString;
import com.google.protobuf.ExtensionRegistryLite;
import com.google.protobuf.InvalidProtocolBufferException;
import java.security.GeneralSecurityException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * Key manager that generates new {@link HpkePrivateKey} keys and produces new instances of {@link
 * HpkeDecrypt} primitives.
 */
public final class HpkePrivateKeyManager
    extends PrivateKeyTypeManager<HpkePrivateKey, HpkePublicKey> {
  public HpkePrivateKeyManager() {
    super(
        HpkePrivateKey.class,
        HpkePublicKey.class,
        new KeyTypeManager.PrimitiveFactory<HybridDecrypt, HpkePrivateKey>(HybridDecrypt.class) {
          @Override
          public HybridDecrypt getPrimitive(HpkePrivateKey recipientPrivateKey)
              throws GeneralSecurityException {
            return HpkeDecrypt.createHpkeDecrypt(recipientPrivateKey);
          }
        });
  }

  /**
   * Registers an {@link HpkePrivateKeyManager} and an {@link HpkePublicKeyManager} with the
   * registry, so that HpkePrivateKey and HpkePublicKey key types can be used with Tink.
   */
  public static void registerPair(boolean newKeyAllowed) throws GeneralSecurityException {
    Registry.registerAsymmetricKeyManagers(
        new HpkePrivateKeyManager(), new HpkePublicKeyManager(), newKeyAllowed);
  }

  @Override
  public String getKeyType() {
    return "type.googleapis.com/google.crypto.tink.HpkePrivateKey";
  }

  @Override
  public int getVersion() {
    return 0;
  }

  @Override
  public HpkePublicKey getPublicKey(HpkePrivateKey key) {
    return key.getPublicKey();
  }

  @Override
  public KeyMaterialType keyMaterialType() {
    return KeyMaterialType.ASYMMETRIC_PRIVATE;
  }

  @Override
  public HpkePrivateKey parseKey(ByteString byteString) throws InvalidProtocolBufferException {
    return HpkePrivateKey.parseFrom(byteString, ExtensionRegistryLite.getEmptyRegistry());
  }

  @Override
  public void validateKey(HpkePrivateKey key) throws GeneralSecurityException {
    if (key.getPrivateKey().isEmpty()) {
      throw new GeneralSecurityException("Private key is empty.");
    }
    if (!key.hasPublicKey()) {
      throw new GeneralSecurityException("Missing public key.");
    }
    Validators.validateVersion(key.getVersion(), getVersion());
    HpkeUtil.validateParams(key.getPublicKey().getParams());
  }

  @Override
  public KeyFactory<HpkeKeyFormat, HpkePrivateKey> keyFactory() {
    return new KeyFactory<HpkeKeyFormat, HpkePrivateKey>(HpkeKeyFormat.class) {
      @Override
      public void validateKeyFormat(HpkeKeyFormat keyFormat) throws GeneralSecurityException {
        HpkeUtil.validateParams(keyFormat.getParams());
      }

      @Override
      public HpkeKeyFormat parseKeyFormat(ByteString byteString)
          throws InvalidProtocolBufferException {
        return HpkeKeyFormat.parseFrom(byteString, ExtensionRegistryLite.getEmptyRegistry());
      }

      @Override
      public HpkePrivateKey createKey(HpkeKeyFormat keyFormat) throws GeneralSecurityException {
        byte[] privateKeyBytes = X25519.generatePrivateKey();
        byte[] publicKeyBytes = X25519.publicFromPrivate(privateKeyBytes);

        HpkePublicKey publicKey =
            HpkePublicKey.newBuilder()
                .setVersion(getVersion())
                .setParams(keyFormat.getParams())
                .setPublicKey(ByteString.copyFrom(publicKeyBytes))
                .build();

        return HpkePrivateKey.newBuilder()
            .setVersion(getVersion())
            .setPublicKey(publicKey)
            .setPrivateKey(ByteString.copyFrom(privateKeyBytes))
            .build();
      }

      @Override
      public Map<String, KeyFactory.KeyFormat<HpkeKeyFormat>> keyFormats() {
        Map<String, KeyFactory.KeyFormat<HpkeKeyFormat>> result = new HashMap<>();
        result.put(
            "DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_128_GCM",
            createKeyFormat(
                HpkeKem.DHKEM_X25519_HKDF_SHA256,
                HpkeKdf.HKDF_SHA256,
                HpkeAead.AES_128_GCM,
                KeyTemplate.OutputPrefixType.TINK));
        result.put(
            "DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_256_GCM",
            createKeyFormat(
                HpkeKem.DHKEM_X25519_HKDF_SHA256,
                HpkeKdf.HKDF_SHA256,
                HpkeAead.AES_256_GCM,
                KeyTemplate.OutputPrefixType.TINK));
        result.put(
            "DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_CHACHA20_POLY1305",
            createKeyFormat(
                HpkeKem.DHKEM_X25519_HKDF_SHA256,
                HpkeKdf.HKDF_SHA256,
                HpkeAead.CHACHA20_POLY1305,
                KeyTemplate.OutputPrefixType.TINK));
        return Collections.unmodifiableMap(result);
      }
    };
  }

  private static KeyFactory.KeyFormat<HpkeKeyFormat> createKeyFormat(
      HpkeKem kem, HpkeKdf kdf, HpkeAead aead, KeyTemplate.OutputPrefixType prefixType) {
    HpkeParams params = HpkeParams.newBuilder().setKem(kem).setKdf(kdf).setAead(aead).build();
    return new KeyFactory.KeyFormat<>(
        HpkeKeyFormat.newBuilder().setParams(params).build(), prefixType);
  }
}
