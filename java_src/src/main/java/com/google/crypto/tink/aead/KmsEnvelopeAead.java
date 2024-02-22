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

package com.google.crypto.tink.aead; // instead of subtle, because it depends on KeyTemplate.

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.Key;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.TinkProtoParametersFormat;
import com.google.crypto.tink.internal.MutableKeyCreationRegistry;
import com.google.crypto.tink.internal.MutablePrimitiveRegistry;
import com.google.crypto.tink.internal.MutableSerializationRegistry;
import com.google.crypto.tink.internal.ProtoKeySerialization;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.proto.KeyTemplate;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.protobuf.ByteString;
import com.google.protobuf.ExtensionRegistryLite;
import com.google.protobuf.InvalidProtocolBufferException;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

/**
 * This primitive implements <a href="https://cloud.google.com/kms/docs/data-encryption-keys">
 * envelope encryption</a>.
 *
 * <p>In envelope encryption, a user generates a data encryption key (DEK) locally, encrypts data
 * with the DEK, sends the DEK to a KMS to be encrypted (with a key managed by KMS), and then stores
 * the encrypted DEK with the encrypted data. At a later point, a user can retrieve the encrypted
 * data and the encyrpted DEK, use the KMS to decrypt the DEK, and use the decrypted DEK to decrypt
 * the data.
 *
 * <p>The ciphertext structure is as follows:
 *
 * <ul>
 *   <li>Length of the encrypted DEK: 4 bytes.
 *   <li>Encrypted DEK: variable length that is equal to the value specified in the last 4 bytes.
 *   <li>AEAD payload: variable length.
 * </ul>
 */
public final class KmsEnvelopeAead implements Aead {
  private static final byte[] EMPTY_AAD = new byte[0];
  private final String typeUrlForParsing;
  private final Parameters parametersForNewKeys;

  private final Aead remote;
  private static final int LENGTH_ENCRYPTED_DEK = 4;

  private static Set<String> listSupportedDekKeyTypes() {
    HashSet<String> dekKeyTypeUrls = new HashSet<>();
    dekKeyTypeUrls.add("type.googleapis.com/google.crypto.tink.AesGcmKey");
    dekKeyTypeUrls.add("type.googleapis.com/google.crypto.tink.ChaCha20Poly1305Key");
    dekKeyTypeUrls.add("type.googleapis.com/google.crypto.tink.XChaCha20Poly1305Key");
    dekKeyTypeUrls.add("type.googleapis.com/google.crypto.tink.AesCtrHmacAeadKey");
    dekKeyTypeUrls.add("type.googleapis.com/google.crypto.tink.AesGcmSivKey");
    dekKeyTypeUrls.add("type.googleapis.com/google.crypto.tink.AesEaxKey");
    return Collections.unmodifiableSet(dekKeyTypeUrls);
  }

  private static final Set<String> supportedDekKeyTypes = listSupportedDekKeyTypes();

  public static boolean isSupportedDekKeyType(String dekKeyTypeUrl) {
    return supportedDekKeyTypes.contains(dekKeyTypeUrl);
  }

  private Parameters getRawParameters(KeyTemplate dekTemplate) throws GeneralSecurityException {
    KeyTemplate rawTemplate =
        KeyTemplate.newBuilder(dekTemplate).setOutputPrefixType(OutputPrefixType.RAW).build();
    return TinkProtoParametersFormat.parse(rawTemplate.toByteArray());
  }

  /**
   * Creates a new KmsEnvelopeAead.
   *
   * <p>This function should be avoided. Instead, if you use this with one of the predefined key
   * templates, call create with the corresponding parameters object.
   *
   * <p>For example, if you use:
   *
   * <p><code>Aead aead = new KmsEnvelopeAead(AeadKeyTemplates.AES128_GCM, remote)</code> you should
   * replace this with:
   *
   * <p><code>Aead aead = KmsEnvelopeAead.create(PredefinedAeadParameters.AES128_GCM, remote)</code>
   *
   * @deprecated Instead, call {@code KmsEnvelopeAead.create} as explained above.
   */
  @Deprecated
  public KmsEnvelopeAead(KeyTemplate dekTemplate, Aead remote)
      throws GeneralSecurityException {
    if (!isSupportedDekKeyType(dekTemplate.getTypeUrl())) {
      throw new IllegalArgumentException(
          "Unsupported DEK key type: "
              + dekTemplate.getTypeUrl()
              + ". Only Tink AEAD key types are supported.");
    }
    this.typeUrlForParsing = dekTemplate.getTypeUrl();
    this.parametersForNewKeys = getRawParameters(dekTemplate);
    this.remote = remote;
  }

  /**
   * Creates a new instance of Tink's KMS Envelope AEAD.
   *
   * <p>{@code dekParameters} must be any of these Tink AEAD parameters (any other will be
   * rejected): {@link AesGcmParameters}, {@link ChaCha20Poly1305Parameters}, {@link
   * XChaCha20Poly1305Parameters}, {@link AesCtrHmacAeadParameters}, {@link AesGcmSivParameters}, or
   * {@link AesEaxParameters}.
   */
  public static Aead create(AeadParameters dekParameters, Aead remote)
      throws GeneralSecurityException {
    // This serializes the parameters, changes output prefix to raw, and parses it again.
    // It would be better to reject the parameters immediately if it was a non-raw object, but
    // this might break someone, so we keep as is.
    KeyTemplate dekTemplate;
    try {
      dekTemplate =
          KeyTemplate.parseFrom(
              TinkProtoParametersFormat.serialize(dekParameters),
              ExtensionRegistryLite.getEmptyRegistry());
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException(e);
    }
    return new KmsEnvelopeAead(dekTemplate, remote);
  }

  @Override
  public byte[] encrypt(final byte[] plaintext, final byte[] associatedData)
      throws GeneralSecurityException {
    Key key =
        MutableKeyCreationRegistry.globalInstance()
            .createKey(parametersForNewKeys, /* idRequirement= */ null);

    ProtoKeySerialization serialization =
        MutableSerializationRegistry.globalInstance()
            .serializeKey(key, ProtoKeySerialization.class, InsecureSecretKeyAccess.get());
    byte[] dek = serialization.getValue().toByteArray();
    // Wrap it with remote.
    byte[] encryptedDek = remote.encrypt(dek, EMPTY_AAD);
    // Use DEK to encrypt plaintext.
    Aead aead = MutablePrimitiveRegistry.globalInstance().getPrimitive(key, Aead.class);
    byte[] payload = aead.encrypt(plaintext, associatedData);
    // Build ciphertext protobuf and return result.
    return buildCiphertext(encryptedDek, payload);
  }

  @Override
  public byte[] decrypt(final byte[] ciphertext, final byte[] associatedData)
      throws GeneralSecurityException {
    try {
      ByteBuffer buffer = ByteBuffer.wrap(ciphertext);
      int encryptedDekSize = buffer.getInt();
      if (encryptedDekSize <= 0 || encryptedDekSize > (ciphertext.length - LENGTH_ENCRYPTED_DEK)) {
        throw new GeneralSecurityException("invalid ciphertext");
      }
      byte[] encryptedDek = new byte[encryptedDekSize];
      buffer.get(encryptedDek, 0, encryptedDekSize);
      byte[] payload = new byte[buffer.remaining()];
      buffer.get(payload, 0, buffer.remaining());
      // Use remote to decrypt encryptedDek.
      byte[] dek = remote.decrypt(encryptedDek, EMPTY_AAD);
      // Use DEK to decrypt payload.
      ProtoKeySerialization serialization =
          ProtoKeySerialization.create(
              typeUrlForParsing,
              ByteString.copyFrom(dek),
              KeyMaterialType.SYMMETRIC,
              OutputPrefixType.RAW,
              /* idRequirement= */ null);
      Key key =
          MutableSerializationRegistry.globalInstance()
              .parseKey(serialization, InsecureSecretKeyAccess.get());

      Aead aead = MutablePrimitiveRegistry.globalInstance().getPrimitive(key, Aead.class);
      return aead.decrypt(payload, associatedData);
    } catch (IndexOutOfBoundsException
             | BufferUnderflowException
             | NegativeArraySizeException e) {
      throw new GeneralSecurityException("invalid ciphertext", e);
    }
  }

  private byte[] buildCiphertext(final byte[] encryptedDek, final byte[] payload) {
    return ByteBuffer.allocate(LENGTH_ENCRYPTED_DEK + encryptedDek.length + payload.length)
        .putInt(encryptedDek.length)
        .put(encryptedDek)
        .put(payload)
        .array();
  }
}
