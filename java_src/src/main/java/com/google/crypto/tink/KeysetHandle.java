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
import com.google.crypto.tink.proto.KeyStatusType;
import com.google.crypto.tink.proto.Keyset;
import com.google.crypto.tink.proto.KeysetInfo;
import com.google.crypto.tink.tinkkey.KeyAccess;
import com.google.crypto.tink.tinkkey.KeyHandle;
import com.google.crypto.tink.tinkkey.internal.InternalKeyHandle;
import com.google.crypto.tink.tinkkey.internal.ProtoKey;
import com.google.protobuf.ByteString;
import com.google.protobuf.ExtensionRegistryLite;
import com.google.protobuf.InvalidProtocolBufferException;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

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
  private final Keyset keyset;

  private KeysetHandle(Keyset keyset) {
    this.keyset = keyset;
  }

  /**
   * @return a new {@link KeysetHandle} from a {@code keyset}.
   * @throws GeneralSecurityException if the keyset is null or empty.
   */
  static final KeysetHandle fromKeyset(Keyset keyset) throws GeneralSecurityException {
    assertEnoughKeyMaterial(keyset);
    return new KeysetHandle(keyset);
  }

  /** @return the actual keyset data. */
  Keyset getKeyset() {
    return keyset;
  }

  /** Returns the keyset data as a list of {@link KeyHandle}s. */
  public List<KeyHandle> getKeys() {
    ArrayList<KeyHandle> result = new ArrayList<>();
    for (Keyset.Key key : keyset.getKeyList()) {
      KeyData keyData = key.getKeyData();
      result.add(
          new InternalKeyHandle(
              new ProtoKey(keyData, KeyTemplate.fromProto(key.getOutputPrefixType())),
              key.getStatus(),
              key.getKeyId()));
    }
    return Collections.unmodifiableList(result);
  }

  /**
   * @return the {@link com.google.crypto.tink.proto.KeysetInfo} that doesn't contain actual key
   *     material.
   */
  public KeysetInfo getKeysetInfo() {
    return Util.getKeysetInfo(keyset);
  }

  /**
   * Generates a new {@link KeysetHandle} that contains a single fresh key generated according to
   * {@code keyTemplate}.
   *
   * @throws GeneralSecurityException if the key template is invalid.
   * @deprecated This method takes a KeyTemplate proto, which is an internal implementation detail.
   *     Please use the generateNew method that takes a {@link KeyTemplate} POJO.
   */
  @Deprecated
  public static final KeysetHandle generateNew(com.google.crypto.tink.proto.KeyTemplate keyTemplate)
      throws GeneralSecurityException {
    return KeysetManager.withEmptyKeyset().rotate(keyTemplate).getKeysetHandle();
  }

  /**
   * Generates a new {@link KeysetHandle} that contains a single fresh key generated according to
   * {@code keyTemplate}.
   *
   * @throws GeneralSecurityException if the key template is invalid.
   */
  public static final KeysetHandle generateNew(KeyTemplate keyTemplate)
      throws GeneralSecurityException {
    return KeysetManager.withEmptyKeyset().rotate(keyTemplate.getProto()).getKeysetHandle();
  }

  /** Creates a {@code KeysetHandle} that contains the single {@code KeyHandle} passed as input. */
  public static final KeysetHandle createFromKey(KeyHandle keyHandle, KeyAccess access)
      throws GeneralSecurityException {
    KeysetManager km = KeysetManager.withEmptyKeyset().add(keyHandle);
    km.setPrimary(km.getKeysetHandle().getKeysetInfo().getKeyInfo(0).getKeyId());
    return km.getKeysetHandle();
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

  /**
   * Tries to create a {@link KeysetHandle} from a keyset, obtained via {@code reader}, which
   * contains no secret key material.
   *
   * <p>This can be used to load public keysets or envelope encryption keysets. Users that need to
   * load cleartext keysets can use {@link CleartextKeysetHandle}.
   *
   * @return a new {@link KeysetHandle} from {@code serialized} that is a serialized {@link Keyset}
   * @throws GeneralSecurityException
   */
  public static final KeysetHandle readNoSecret(KeysetReader reader)
      throws GeneralSecurityException, IOException {
    try {
      Keyset keyset = reader.read();
      assertNoSecretKeyMaterial(keyset);
      return KeysetHandle.fromKeyset(keyset);
    } catch (
        @SuppressWarnings("UnusedException")
        InvalidProtocolBufferException e) {
      // Do not propagate InvalidProtocolBufferException to guarantee no key material is leaked
      throw new GeneralSecurityException("invalid keyset");
    }
  }

  /**
   * Tries to create a {@link KeysetHandle} from a serialized keyset which contains no secret key
   * material.
   *
   * <p>This can be used to load public keysets or envelope encryption keysets. Users that need to
   * load cleartext keysets can use {@link CleartextKeysetHandle}.
   *
   * @return a new {@link KeysetHandle} from {@code serialized} that is a serialized {@link Keyset}
   * @throws GeneralSecurityException
   */
  public static final KeysetHandle readNoSecret(final byte[] serialized)
      throws GeneralSecurityException {
    try {
      Keyset keyset = Keyset.parseFrom(serialized, ExtensionRegistryLite.getEmptyRegistry());
      assertNoSecretKeyMaterial(keyset);
      return KeysetHandle.fromKeyset(keyset);
    } catch (
        @SuppressWarnings("UnusedException")
        InvalidProtocolBufferException e) {
      // Do not propagate InvalidProtocolBufferException to guarantee no key material is leaked
      throw new GeneralSecurityException("invalid keyset");
    }
  }

  /** Serializes, encrypts with {@code masterKey} and writes the keyset to {@code outputStream}. */
  public void write(KeysetWriter keysetWriter, Aead masterKey)
      throws GeneralSecurityException, IOException {
    EncryptedKeyset encryptedKeyset = encrypt(keyset, masterKey);
    keysetWriter.write(encryptedKeyset);
    return;
  }

  /**
   * Tries to write to {@code writer} this keyset which must not contain any secret key material.
   *
   * <p>This can be used to persist public keysets or envelope encryption keysets. Users that need
   * to persist cleartext keysets can use {@link CleartextKeysetHandle}.
   *
   * @throws GeneralSecurityException if the keyset contains any secret key material
   */
  public void writeNoSecret(KeysetWriter writer) throws GeneralSecurityException, IOException {
    assertNoSecretKeyMaterial(keyset);
    writer.write(keyset);
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
          Keyset.parseFrom(
              masterKey.decrypt(encryptedKeyset, /* associatedData= */ new byte[0]),
              ExtensionRegistryLite.getEmptyRegistry());
      if (!keyset2.equals(keyset)) {
        throw new GeneralSecurityException("cannot encrypt keyset");
      }
    } catch (
        @SuppressWarnings("UnusedException")
        InvalidProtocolBufferException e) {
      // Do not propagate InvalidProtocolBufferException to guarantee no key material is leaked
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
                  /* associatedData= */ new byte[0]),
              ExtensionRegistryLite.getEmptyRegistry());
      // check emptiness here too, in case the encrypted keys unwrapped to nothing?
      assertEnoughKeyMaterial(keyset);
      return keyset;
    } catch (
        @SuppressWarnings("UnusedException")
        InvalidProtocolBufferException e) {
      // Do not propagate InvalidProtocolBufferException to guarantee no key material is leaked
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

  @SuppressWarnings("deprecation")
  private static void validate(KeyData keyData) throws GeneralSecurityException {
    // This will throw GeneralSecurityException if the keyData is invalid.
    Registry.getPrimitive(keyData);
  }

  /**
   * Extracts and returns the string representation of the {@link
   * com.google.crypto.tink.proto.KeysetInfo} of the managed keyset.
   */
  @SuppressWarnings("LiteProtoToString") // main purpose of toString is for debugging
  @Override
  public String toString() {
    return getKeysetInfo().toString();
  }

  /**
   * Validates that {@code keyset} doesn't contain any secret key material.
   *
   * @throws GeneralSecurityException if {@code keyset} contains secret key material.
   */
  private static void assertNoSecretKeyMaterial(Keyset keyset) throws GeneralSecurityException {
    for (Keyset.Key key : keyset.getKeyList()) {
      if (key.getKeyData().getKeyMaterialType() == KeyData.KeyMaterialType.UNKNOWN_KEYMATERIAL
          || key.getKeyData().getKeyMaterialType() == KeyData.KeyMaterialType.SYMMETRIC
          || key.getKeyData().getKeyMaterialType() == KeyData.KeyMaterialType.ASYMMETRIC_PRIVATE) {
        throw new GeneralSecurityException(
            String.format(
                "keyset contains key material of type %s for type url %s",
                key.getKeyData().getKeyMaterialType().name(), key.getKeyData().getTypeUrl()));
      }
    }
  }

  /**
   * Validates that a keyset handle contains enough key material to build a keyset on.
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

  /** Helper function to allow us to have a a name {@code B} for the base primitive. */
  private <B, P> P getPrimitiveWithKnownInputPrimitive(
      Class<P> classObject, Class<B> inputPrimitiveClassObject) throws GeneralSecurityException {
    Util.validateKeyset(keyset);
    PrimitiveSet<B> primitives = PrimitiveSet.newPrimitiveSet(inputPrimitiveClassObject);
    for (Keyset.Key key : keyset.getKeyList()) {
      if (key.getStatus() == KeyStatusType.ENABLED) {
        B primitive = Registry.getPrimitive(key.getKeyData(), inputPrimitiveClassObject);
        PrimitiveSet.Entry<B> entry = primitives.addPrimitive(primitive, key);
        if (key.getKeyId() == keyset.getPrimaryKeyId()) {
          primitives.setPrimary(entry);
        }
      }
    }

    return Registry.wrap(primitives, classObject);
  }

  /**
   * Returns a primitive from this keyset, using the global registry to create resources creating
   * the primitive.
   */
  public <P> P getPrimitive(Class<P> targetClassObject) throws GeneralSecurityException {
    Class<?> inputPrimitiveClassObject = Registry.getInputPrimitive(targetClassObject);
    if (inputPrimitiveClassObject == null) {
      throw new GeneralSecurityException("No wrapper found for " + targetClassObject.getName());
    }
    return getPrimitiveWithKnownInputPrimitive(targetClassObject, inputPrimitiveClassObject);
  }

  /**
   * Searches the keyset to find the primary key of this {@code KeysetHandle}, and returns the key
   * wrapped in a {@code KeyHandle}.
   */
  public KeyHandle primaryKey() throws GeneralSecurityException {
    int primaryKeyId = keyset.getPrimaryKeyId();
    for (Keyset.Key key : keyset.getKeyList()) {
      if (key.getKeyId() == primaryKeyId) {
        return new InternalKeyHandle(
            new ProtoKey(key.getKeyData(), KeyTemplate.fromProto(key.getOutputPrefixType())),
            key.getStatus(),
            key.getKeyId());
      }
    }
    throw new GeneralSecurityException("No primary key found in keyset.");
  }
}
