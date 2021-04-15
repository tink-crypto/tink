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

import com.google.crypto.tink.KeyTemplate;
import com.google.crypto.tink.KeyTypeManager;
import com.google.crypto.tink.PrivateKeyTypeManager;
import com.google.crypto.tink.PublicKeySign;
import com.google.crypto.tink.Registry;
import com.google.crypto.tink.proto.Ed25519KeyFormat;
import com.google.crypto.tink.proto.Ed25519PrivateKey;
import com.google.crypto.tink.proto.Ed25519PublicKey;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.subtle.Ed25519Sign;
import com.google.crypto.tink.subtle.Validators;
import com.google.protobuf.ByteString;
import com.google.protobuf.ExtensionRegistryLite;
import com.google.protobuf.InvalidProtocolBufferException;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * This instance of {@code KeyManager} generates new {@code Ed25519PrivateKey} keys and produces new
 * instances of {@code Ed25519Sign}.
 */
public final class Ed25519PrivateKeyManager
    extends PrivateKeyTypeManager<Ed25519PrivateKey, Ed25519PublicKey> {
  Ed25519PrivateKeyManager() {
    super(
        Ed25519PrivateKey.class,
        Ed25519PublicKey.class,
        new KeyTypeManager.PrimitiveFactory<PublicKeySign, Ed25519PrivateKey>(PublicKeySign.class) {
          @Override
          public PublicKeySign getPrimitive(Ed25519PrivateKey keyProto)
              throws GeneralSecurityException {
            return new Ed25519Sign(keyProto.getKeyValue().toByteArray());
          }
        });
  }

  @Override
  public String getKeyType() {
    return "type.googleapis.com/google.crypto.tink.Ed25519PrivateKey";
  }

  @Override
  public int getVersion() {
    return 0;
  }

  @Override
  public Ed25519PublicKey getPublicKey(Ed25519PrivateKey key) throws GeneralSecurityException {
    return key.getPublicKey();
  }

  @Override
  public KeyMaterialType keyMaterialType() {
    return KeyMaterialType.ASYMMETRIC_PRIVATE;
  }

  @Override
  public Ed25519PrivateKey parseKey(ByteString byteString) throws InvalidProtocolBufferException {
    return Ed25519PrivateKey.parseFrom(byteString, ExtensionRegistryLite.getEmptyRegistry());
  }

  @Override
  public void validateKey(Ed25519PrivateKey keyProto) throws GeneralSecurityException {
    Validators.validateVersion(keyProto.getVersion(), getVersion());
    new Ed25519PublicKeyManager().validateKey(keyProto.getPublicKey());
    if (keyProto.getKeyValue().size() != Ed25519Sign.SECRET_KEY_LEN) {
      throw new GeneralSecurityException("invalid Ed25519 private key: incorrect key length");
    }
  }

  @Override
  public KeyFactory<Ed25519KeyFormat, Ed25519PrivateKey> keyFactory() {
    return new KeyFactory<Ed25519KeyFormat, Ed25519PrivateKey>(Ed25519KeyFormat.class) {
      @Override
      public void validateKeyFormat(Ed25519KeyFormat format) throws GeneralSecurityException {}

      @Override
      public Ed25519KeyFormat parseKeyFormat(ByteString byteString)
          throws InvalidProtocolBufferException {
        return Ed25519KeyFormat.parseFrom(byteString, ExtensionRegistryLite.getEmptyRegistry());
      }

      @Override
      public Ed25519PrivateKey createKey(Ed25519KeyFormat format) throws GeneralSecurityException {
        Ed25519Sign.KeyPair keyPair = Ed25519Sign.KeyPair.newKeyPair();
        Ed25519PublicKey publicKey =
            Ed25519PublicKey.newBuilder()
                .setVersion(getVersion())
                .setKeyValue(ByteString.copyFrom(keyPair.getPublicKey()))
                .build();
        return Ed25519PrivateKey.newBuilder()
            .setVersion(getVersion())
            .setKeyValue(ByteString.copyFrom(keyPair.getPrivateKey()))
            .setPublicKey(publicKey)
            .build();
      }

      @Override
      public Ed25519PrivateKey deriveKey(Ed25519KeyFormat format, InputStream inputStream)
          throws GeneralSecurityException {
        Validators.validateVersion(format.getVersion(), getVersion());

        byte[] pseudorandomness = new byte[Ed25519Sign.SECRET_KEY_LEN];
        try {
          int read = inputStream.read(pseudorandomness);
          if (read != Ed25519Sign.SECRET_KEY_LEN) {
            throw new GeneralSecurityException("Not enough pseudorandomness given");
          }
          Ed25519Sign.KeyPair keyPair = Ed25519Sign.KeyPair.newKeyPairFromSeed(pseudorandomness);
          Ed25519PublicKey publicKey =
              Ed25519PublicKey.newBuilder()
                  .setVersion(getVersion())
                  .setKeyValue(ByteString.copyFrom(keyPair.getPublicKey()))
                  .build();
          return Ed25519PrivateKey.newBuilder()
              .setVersion(getVersion())
              .setKeyValue(ByteString.copyFrom(keyPair.getPrivateKey()))
              .setPublicKey(publicKey)
              .build();
        } catch (IOException e) {
          throw new GeneralSecurityException("Reading pseudorandomness failed", e);
        }
      }

      @Override
      public Map<String, KeyFactory.KeyFormat<Ed25519KeyFormat>> keyFormats()
          throws GeneralSecurityException {
        Map<String, KeyFactory.KeyFormat<Ed25519KeyFormat>> result = new HashMap<>();
        result.put(
            "ED25519",
            new KeyFormat<>(
                Ed25519KeyFormat.getDefaultInstance(), KeyTemplate.OutputPrefixType.TINK));
        result.put(
            "ED25519_RAW",
            new KeyFormat<>(
                Ed25519KeyFormat.getDefaultInstance(), KeyTemplate.OutputPrefixType.RAW));
        // This is identical to ED25519_RAW.
        // It is needed to maintain backward compatibility with SignatureKeyTemplates.
        // TODO(b/185475349): remove this in 2.0.0.
        result.put(
            "ED25519WithRawOutput",
            new KeyFormat<>(
                Ed25519KeyFormat.getDefaultInstance(), KeyTemplate.OutputPrefixType.RAW));
        return Collections.unmodifiableMap(result);
      }
    };
  }

  /**
   * Registers the {@link Ed25519PrivateKeyManager} and the {@link Ed25519PublicKeyManager} with the
   * registry, so that the the Ed25519-Keys can be used with Tink.
   */
  public static void registerPair(boolean newKeyAllowed) throws GeneralSecurityException {
    Registry.registerAsymmetricKeyManagers(
        new Ed25519PrivateKeyManager(), new Ed25519PublicKeyManager(), newKeyAllowed);
  }

  /** @return A {@link KeyTemplate} that generates new instances of ED25519 keys. */
  public static final KeyTemplate ed25519Template() {
    return KeyTemplate.create(
        new Ed25519PrivateKeyManager().getKeyType(),
        /*value=*/ new byte[0],
        KeyTemplate.OutputPrefixType.TINK);
  }

  /**
   * @return A {@link KeyTemplate} that generates new instances of Ed25519 keys. Keys generated from
   *     this template creates raw signatures of exactly 64 bytes. It's compatible with most other
   *     libraries.
   */
  public static final KeyTemplate rawEd25519Template() {
    return KeyTemplate.create(
        new Ed25519PrivateKeyManager().getKeyType(),
        /*value=*/ new byte[0],
        KeyTemplate.OutputPrefixType.RAW);
  }
}
