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

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.KeyTemplate;
import com.google.crypto.tink.KeyTypeManager;
import com.google.crypto.tink.Registry;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.proto.XChaCha20Poly1305Key;
import com.google.crypto.tink.proto.XChaCha20Poly1305KeyFormat;
import com.google.crypto.tink.subtle.Random;
import com.google.crypto.tink.subtle.Validators;
import com.google.crypto.tink.subtle.XChaCha20Poly1305;
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
 * This instance of {@code KeyManager} generates new {@code XChaCha20Poly1305} keys and produces new
 * instances of {@code XChaCha20Poly1305}.
 */
public class XChaCha20Poly1305KeyManager extends KeyTypeManager<XChaCha20Poly1305Key> {
  XChaCha20Poly1305KeyManager() {
    super(
        XChaCha20Poly1305Key.class,
        new PrimitiveFactory<Aead, XChaCha20Poly1305Key>(Aead.class) {
          @Override
          public Aead getPrimitive(XChaCha20Poly1305Key key) throws GeneralSecurityException {
            return new XChaCha20Poly1305(key.getKeyValue().toByteArray());
          }
        });
  }

  private static final int KEY_SIZE_IN_BYTES = 32;

  @Override
  public String getKeyType() {
    return "type.googleapis.com/google.crypto.tink.XChaCha20Poly1305Key";
  }

  @Override
  public int getVersion() {
    return 0;
  }

  @Override
  public KeyMaterialType keyMaterialType() {
    return KeyMaterialType.SYMMETRIC;
  }

  @Override
  public void validateKey(XChaCha20Poly1305Key key) throws GeneralSecurityException {
    Validators.validateVersion(key.getVersion(), getVersion());
    if (key.getKeyValue().size() != KEY_SIZE_IN_BYTES) {
      throw new GeneralSecurityException("invalid XChaCha20Poly1305Key: incorrect key length");
    }
  }

  @Override
  public XChaCha20Poly1305Key parseKey(ByteString byteString)
      throws InvalidProtocolBufferException {
    return XChaCha20Poly1305Key.parseFrom(byteString, ExtensionRegistryLite.getEmptyRegistry());
  }

  @Override
  public KeyFactory<XChaCha20Poly1305KeyFormat, XChaCha20Poly1305Key> keyFactory() {
    return new KeyFactory<XChaCha20Poly1305KeyFormat, XChaCha20Poly1305Key>(
        XChaCha20Poly1305KeyFormat.class) {
      @Override
      public void validateKeyFormat(XChaCha20Poly1305KeyFormat format)
          throws GeneralSecurityException {}

      @Override
      public XChaCha20Poly1305KeyFormat parseKeyFormat(ByteString byteString)
          throws InvalidProtocolBufferException {
        return XChaCha20Poly1305KeyFormat.parseFrom(
            byteString, ExtensionRegistryLite.getEmptyRegistry());
      }

      @Override
      public XChaCha20Poly1305Key createKey(XChaCha20Poly1305KeyFormat format)
          throws GeneralSecurityException {
        return XChaCha20Poly1305Key.newBuilder()
            .setVersion(getVersion())
            .setKeyValue(ByteString.copyFrom(Random.randBytes(KEY_SIZE_IN_BYTES)))
            .build();
      }

      @Override
      public XChaCha20Poly1305Key deriveKey(
          XChaCha20Poly1305KeyFormat format, InputStream inputStream)
          throws GeneralSecurityException {
        Validators.validateVersion(format.getVersion(), getVersion());

        byte[] pseudorandomness = new byte[KEY_SIZE_IN_BYTES];
        try {
          int read = inputStream.read(pseudorandomness);
          if (read != KEY_SIZE_IN_BYTES) {
            throw new GeneralSecurityException("Not enough pseudorandomness given");
          }
          return XChaCha20Poly1305Key.newBuilder()
              .setKeyValue(ByteString.copyFrom(pseudorandomness))
              .setVersion(getVersion())
              .build();
        } catch (IOException e) {
          throw new GeneralSecurityException("Reading pseudorandomness failed", e);
        }
      }

      @Override
      public Map<String, KeyFactory.KeyFormat<XChaCha20Poly1305KeyFormat>> keyFormats() {
        Map<String, KeyFactory.KeyFormat<XChaCha20Poly1305KeyFormat>> result = new HashMap<>();
        result.put(
            "XCHACHA20_POLY1305",
            new KeyFactory.KeyFormat<>(
                XChaCha20Poly1305KeyFormat.getDefaultInstance(),
                KeyTemplate.OutputPrefixType.TINK));
        result.put(
            "XCHACHA20_POLY1305_RAW",
            new KeyFactory.KeyFormat<>(
                XChaCha20Poly1305KeyFormat.getDefaultInstance(), KeyTemplate.OutputPrefixType.RAW));
        return Collections.unmodifiableMap(result);
      }
    };
  }

  public static void register(boolean newKeyAllowed) throws GeneralSecurityException {
    Registry.registerKeyManager(new XChaCha20Poly1305KeyManager(), newKeyAllowed);
  }

  /** @return a {@link KeyTemplate} that generates new instances of XChaCha20Poly1305 keys. */
  public static final KeyTemplate xChaCha20Poly1305Template() {
    return KeyTemplate.create(
        new XChaCha20Poly1305KeyManager().getKeyType(),
        XChaCha20Poly1305KeyFormat.getDefaultInstance().toByteArray(),
        KeyTemplate.OutputPrefixType.TINK);
  }

  /**
   * @return a {@link KeyTemplate} that generates new instances of XChaCha20Poly1305 keys. Keys
   *     generated from this template create ciphertexts compatible with libsodium and other
   *     libraries.
   */
  public static final KeyTemplate rawXChaCha20Poly1305Template() {
    return KeyTemplate.create(
        new XChaCha20Poly1305KeyManager().getKeyType(),
        XChaCha20Poly1305KeyFormat.getDefaultInstance().toByteArray(),
        KeyTemplate.OutputPrefixType.RAW);
  }
}
