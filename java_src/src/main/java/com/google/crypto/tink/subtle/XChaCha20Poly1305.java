// Copyright 2018 Google Inc.
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

package com.google.crypto.tink.subtle;

import static com.google.crypto.tink.internal.Util.isPrefix;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.Aead;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.aead.XChaCha20Poly1305Key;
import com.google.crypto.tink.aead.internal.InsecureNonceXChaCha20Poly1305;
import com.google.crypto.tink.aead.internal.Poly1305;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.util.Arrays;

/**
 * XChaCha20Poly1305 AEAD construction, as described in
 * https://tools.ietf.org/html/draft-arciszewski-xchacha-01.
 */
public final class XChaCha20Poly1305 implements Aead {
  private final InsecureNonceXChaCha20Poly1305 cipher;
  private final byte[] outputPrefix;

  private XChaCha20Poly1305(final byte[] key, final byte[] outputPrefix)
      throws GeneralSecurityException {
    cipher = new InsecureNonceXChaCha20Poly1305(key);
    this.outputPrefix = outputPrefix;
  }

  public XChaCha20Poly1305(final byte[] key) throws GeneralSecurityException {
    this(key, new byte[0]);
  }

  @AccessesPartialKey
  public static Aead create(XChaCha20Poly1305Key key) throws GeneralSecurityException {
    return new XChaCha20Poly1305(
        key.getKeyBytes().toByteArray(InsecureSecretKeyAccess.get()),
        key.getOutputPrefix().toByteArray());
  }

  private byte[] rawEncrypt(final byte[] plaintext, final byte[] associatedData)
      throws GeneralSecurityException {
    ByteBuffer output =
        ByteBuffer.allocate(
            XChaCha20.NONCE_LENGTH_IN_BYTES + plaintext.length + Poly1305.MAC_TAG_SIZE_IN_BYTES);
    byte[] nonce = Random.randBytes(XChaCha20.NONCE_LENGTH_IN_BYTES);
    output.put(nonce); // Prepend nonce to ciphertext output.
    cipher.encrypt(output, nonce, plaintext, associatedData);
    return output.array();
  }

  @Override
  public byte[] encrypt(final byte[] plaintext, final byte[] associatedData)
      throws GeneralSecurityException {
    byte[] ciphertext = rawEncrypt(plaintext, associatedData);
    if (outputPrefix.length == 0) {
      return ciphertext;
    }
    return Bytes.concat(outputPrefix, ciphertext);
  }

  private byte[] rawDecrypt(final byte[] ciphertext, final byte[] associatedData)
      throws GeneralSecurityException {
    if (ciphertext.length < XChaCha20.NONCE_LENGTH_IN_BYTES + Poly1305.MAC_TAG_SIZE_IN_BYTES) {
      throw new GeneralSecurityException("ciphertext too short");
    }
    byte[] nonce = Arrays.copyOf(ciphertext, XChaCha20.NONCE_LENGTH_IN_BYTES);
    ByteBuffer rawCiphertext =
        ByteBuffer.wrap(
            ciphertext,
            XChaCha20.NONCE_LENGTH_IN_BYTES,
            ciphertext.length - XChaCha20.NONCE_LENGTH_IN_BYTES);
    return cipher.decrypt(rawCiphertext, nonce, associatedData);
  }

  @Override
  public byte[] decrypt(final byte[] ciphertext, final byte[] associatedData)
      throws GeneralSecurityException {
    if (outputPrefix.length == 0) {
      return rawDecrypt(ciphertext, associatedData);
    }
    if (!isPrefix(outputPrefix, ciphertext)) {
      throw new GeneralSecurityException("Decryption failed (OutputPrefix mismatch).");
    }
    byte[] copiedCiphertext =
        Arrays.copyOfRange(ciphertext, outputPrefix.length, ciphertext.length);
    return rawDecrypt(copiedCiphertext, associatedData);
  }
}
