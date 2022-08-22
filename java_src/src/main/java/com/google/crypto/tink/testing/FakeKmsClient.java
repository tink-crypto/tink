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

package com.google.crypto.tink.testing;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.BinaryKeysetReader;
import com.google.crypto.tink.BinaryKeysetWriter;
import com.google.crypto.tink.CleartextKeysetHandle;
import com.google.crypto.tink.KeyTemplate;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.KmsClient;
import com.google.crypto.tink.aead.AesCtrHmacAeadKeyManager;
import com.google.crypto.tink.proto.Keyset;
import com.google.crypto.tink.subtle.Base64;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Locale;

/** An implementation of a fake {@link KmsClient}. */
public final class FakeKmsClient implements KmsClient {
  /** The prefix of all fake KMS keys. */
  public static final String PREFIX = "fake-kms://";

  private String keyUri;

  /** Constructs a generic FakeKmsClient that is not bound to any specific key. */
  public FakeKmsClient() {}

  /** Constructs a specific FakeKmsClient that is bound to the key identified by {@code uri}. */
  public FakeKmsClient(String uri) {
    if (!uri.toLowerCase().startsWith(PREFIX)) {
      throw new IllegalArgumentException("key URI must starts with " + PREFIX);
    }
    this.keyUri = uri;
  }

  /**
   * @return true either if this client is a generic one and uri starts with {@link
   *     FakeKmsClient#PREFIX}, or the client is a specific one that is bound to the key identified
   *     by {@code uri}.
   */
  @Override
  public boolean doesSupport(String uri) {
    if (this.keyUri != null && this.keyUri.equals(uri)) {
      return true;
    }
    return this.keyUri == null && uri.toLowerCase().startsWith(PREFIX);
  }

  @Override
  public KmsClient withCredentials(String credentialPath) throws GeneralSecurityException {
    return this;
  }

  @Override
  public KmsClient withDefaultCredentials() throws GeneralSecurityException {
    return this;
  }

  private static String removePrefix(String expectedPrefix, String kmsKeyUri) {
    if (!kmsKeyUri.toLowerCase(Locale.US).startsWith(expectedPrefix)) {
      throw new IllegalArgumentException(
          String.format("key URI must start with %s", expectedPrefix));
    }
    return kmsKeyUri.substring(expectedPrefix.length());
  }

  @Override
  public Aead getAead(String uri) throws GeneralSecurityException {
    if (this.keyUri != null && !this.keyUri.equals(uri)) {
      throw new GeneralSecurityException(
          String.format(
              "this client is bound to %s, cannot load keys bound to %s", this.keyUri, uri));
    }
    String encodedKey = removePrefix(PREFIX, uri);
    byte[] bytes = Base64.urlSafeDecode(encodedKey);
    try {
      KeysetHandle keysetHandle = CleartextKeysetHandle.read(BinaryKeysetReader.withBytes(bytes));
      return keysetHandle.getPrimitive(Aead.class);
    } catch (IOException e) {
      throw new GeneralSecurityException("Failed to create AEAD ", e);
    }
  }

  /** @return a new, random fake key_uri. */
  public static String createFakeKeyUri() throws GeneralSecurityException {
    // The key_uri contains an encoded keyset with a new aes128CtrHmacSha256 key.
    KeyTemplate template = AesCtrHmacAeadKeyManager.aes128CtrHmacSha256Template();
    KeysetHandle keysetHandle = KeysetHandle.generateNew(template);
    Keyset keyset = CleartextKeysetHandle.getKeyset(keysetHandle);
    ByteArrayOutputStream keysetStream = new ByteArrayOutputStream();
    try {
      BinaryKeysetWriter.withOutputStream(keysetStream).write(keyset);
      keysetStream.close();
    } catch (IOException e) {
      throw new GeneralSecurityException("Failed to create key URI ", e);
    }
    String encodedKey = Base64.urlSafeEncode(keysetStream.toByteArray());
    return PREFIX + encodedKey;
  }


}
