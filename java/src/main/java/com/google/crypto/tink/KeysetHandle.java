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

package com.google.crypto.tink;

import com.google.crypto.tink.proto.EncryptedKeyset;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.proto.KeyTemplate;
import com.google.crypto.tink.proto.Keyset;
import com.google.crypto.tink.proto.KeysetInfo;
import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import java.io.IOException;
import java.security.GeneralSecurityException;

/**
 * A KeysetHandle provides abstracted access to {@link Keyset}, to limit the exposure of actual
 * protocol buffers that hold sensitive key material.
 *
 * <p>This class allows reading and writing encrypted keysets. Users that want to read or write can
 * use the restricted API {@link CleartextKeysetHandle}. Users can also load keysets that don't
 * contain any secret key material with {@link NoSecretKeysetHandle}.
 *
 * @since 1.0.0
 */
public final class KeysetHandle {
  private Keyset keyset;

  private KeysetHandle(Keyset keyset) {
    this.keyset = keyset;
  }

  /**
   * @return a new {@link KeysetHandle} from a {@code keyset}.
   * @throws GeneralSecurityException
   */
  static final KeysetHandle fromKeyset(Keyset keyset) throws GeneralSecurityException {
    assertEnoughKeyMaterial(keyset);
    return new KeysetHandle(keyset);
  }

  /** @return the actual keyset data. */
  Keyset getKeyset() {
    return keyset;
  }

  /**
   * @return the {@link com.google.crypto.tink.proto.KeysetInfo} that doesn't contain actual key
   *     material.
   */
  public KeysetInfo getKeysetInfo() {
    return Util.getKeysetInfo(keyset);
  }

  /**
   * @return a new {@link KeysetHandle} that contains a single fresh key generated according to
   *     {@code keyTemplate}.
   * @throws GeneralSecurityException
   */
  public static final KeysetHandle generateNew(KeyTemplate keyTemplate)
      throws GeneralSecurityException {
    return KeysetManager.withEmptyKeyset().rotate(keyTemplate).getKeysetHandle();
  }

  /**
   * Tries to create a {@link KeysetHandle} from an encrypted keyset obtained via {@code reader}.
   *
   * <p>Users that need to load cleartext keysets can use {@link CleartextKeysetHandle}.
   *
   * @return a new {@link KeysetHandle} from {@code encryptedKeysetProto} that was encrypted with
   *     {@code masterKey}
   * @throws GeneralSecurityException if cannot decrypt the keyset or it doesn't contain encrypted
   *     key material
   */
  public static final KeysetHandle read(KeysetReader reader, Aead masterKey)
      throws GeneralSecurityException, IOException {
    EncryptedKeyset encryptedKeyset = reader.readEncrypted();
    assertEnoughEncryptedKeyMaterial(encryptedKeyset);
    return new KeysetHandle(decrypt(encryptedKeyset, masterKey));
  }

  /** Serializes, encrypts with {@code masterKey} and writes the keyset to {@code outputStream}. */
  public void write(KeysetWriter keysetWriter, Aead masterKey)
      throws GeneralSecurityException, IOException {
    EncryptedKeyset encryptedKeyset = encrypt(keyset, masterKey);
    keysetWriter.write(encryptedKeyset);
    return;
  }

  /** Encrypts the keyset with the {@link Aead} master key. */
  private static EncryptedKeyset encrypt(Keyset keyset, Aead masterKey)
      throws GeneralSecurityException {
    byte[] encryptedKeyset =
        masterKey.encrypt(keyset.toByteArray(), /* associatedData= */ new byte[0]);
    // Check if we can decrypt, to detect errors
    try {
      final Keyset keyset2 =
          Keyset.parseFrom(masterKey.decrypt(encryptedKeyset, /* associatedData= */ new byte[0]));
      if (!keyset2.equals(keyset)) {
        throw new GeneralSecurityException("cannot encrypt keyset");
      }
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("invalid keyset, corrupted key material");
    }
    return EncryptedKeyset.newBuilder()
        .setEncryptedKeyset(ByteString.copyFrom(encryptedKeyset))
        .setKeysetInfo(Util.getKeysetInfo(keyset))
        .build();
  }

  /** Decrypts the encrypted keyset with the {@link Aead} master key. */
  private static Keyset decrypt(EncryptedKeyset encryptedKeyset, Aead masterKey)
      throws GeneralSecurityException {
    try {
      Keyset keyset =
          Keyset.parseFrom(
              masterKey.decrypt(
                  encryptedKeyset.getEncryptedKeyset().toByteArray(),
                  /* associatedData= */ new byte[0]));
      // check emptiness here too, in case the encrypted keys unwrapped to nothing?
      assertEnoughKeyMaterial(keyset);
      return keyset;
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("invalid keyset, corrupted key material");
    }
  }

  /**
   * If the managed keyset contains private keys, returns a {@link KeysetHandle} of the public keys.
   *
   * @throws GenernalSecurityException if the managed keyset is null or if it contains any
   *     non-private keys.
   */
  public KeysetHandle getPublicKeysetHandle() throws GeneralSecurityException {
    if (keyset == null) {
      throw new GeneralSecurityException("cleartext keyset is not available");
    }
    Keyset.Builder keysetBuilder = Keyset.newBuilder();
    for (Keyset.Key key : keyset.getKeyList()) {
      KeyData keyData = createPublicKeyData(key.getKeyData());
      keysetBuilder.addKey(Keyset.Key.newBuilder().mergeFrom(key).setKeyData(keyData).build());
    }
    keysetBuilder.setPrimaryKeyId(keyset.getPrimaryKeyId());
    return new KeysetHandle(keysetBuilder.build());
  }

  private static KeyData createPublicKeyData(KeyData privateKeyData)
      throws GeneralSecurityException {
    if (privateKeyData.getKeyMaterialType() != KeyData.KeyMaterialType.ASYMMETRIC_PRIVATE) {
      throw new GeneralSecurityException("The keyset contains a non-private key");
    }
    KeyData publicKeyData =
        Registry.getPublicKeyData(privateKeyData.getTypeUrl(), privateKeyData.getValue());
    validate(publicKeyData);
    return publicKeyData;
  }

  private static void validate(KeyData keyData) throws GeneralSecurityException {
    // This will throw GeneralSecurityException if the keyData is invalid.
    Registry.getPrimitive(keyData);
  }

  /**
   * Extracts and returns the string representation of the {@link
   * com.google.crypto.tink.proto.KeysetInfo} of the managed keyset.
   */
  @Override
  public String toString() {
    return getKeysetInfo().toString();
  }

  /**
   * Validates that an keyset handle contains enough key material to build a keyset on.
   *
   * @throws GeneralSecurityException
   */
  public static void assertEnoughKeyMaterial(Keyset keyset) throws GeneralSecurityException {
    if (keyset == null || keyset.getKeyCount() <= 0) {
      throw new GeneralSecurityException("empty keyset");
    }
  }

  /**
   * Validates that an encrypted keyset contains enough key material to build a keyset on.
   *
   * @throws GeneralSecurityException
   */
  public static void assertEnoughEncryptedKeyMaterial(EncryptedKeyset keyset)
      throws GeneralSecurityException {
    if (keyset == null || keyset.getEncryptedKeyset().size() == 0) {
      throw new GeneralSecurityException("empty keyset");
    }
  }
}
