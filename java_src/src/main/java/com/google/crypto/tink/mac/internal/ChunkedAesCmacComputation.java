// Copyright 2022 Google LLC
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

package com.google.crypto.tink.mac.internal;

import static java.lang.Math.min;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.mac.AesCmacKey;
import com.google.crypto.tink.mac.AesCmacParameters.Variant;
import com.google.crypto.tink.mac.ChunkedMacComputation;
import com.google.crypto.tink.subtle.Bytes;
import com.google.crypto.tink.subtle.EngineFactory;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

/**
 * An implementation of streaming CMAC computation following
 * tink/java_src/src/main/java/com/google/crypto/tink/subtle/PrfAesCmac.java's vision of <a
 * href="https://tools.ietf.org/html/rfc4493">RFC 4493</a>.
 */
@AccessesPartialKey
final class ChunkedAesCmacComputation implements ChunkedMacComputation {
  // A single byte to be added to the plaintext for the legacy key type.
  private static final byte[] FORMAT_VERSION = new byte[] {0};

  private final Cipher aes;
  private final AesCmacKey key;
  // subKey1 and subKey2 are derived as in RFC 4493.
  private final byte[] subKey1;
  private final byte[] subKey2;
  /**
   * We need this AES-block sized buffer in order to account for the possibility of data not
   * arriving in perfect blocks, and also because we never know which block is going to be the last,
   * so we need to cache some data unprocessed between calls to update().
   *
   * Invariant: between calls we have: 0 <= localStash.position < 16, and localStash is a suffix of
   * data so far, such that the rest is divisible by 16.
   */
  private final ByteBuffer localStash;
  /* x and y contain the contents as in RFC 4493. */
  private final ByteBuffer x;
  private final ByteBuffer y;

  private boolean finalized = false;

  ChunkedAesCmacComputation(AesCmacKey key) throws GeneralSecurityException {
    this.key = key;
    aes = EngineFactory.CIPHER.getInstance("AES/ECB/NoPadding");
    aes.init(
        Cipher.ENCRYPT_MODE,
        new SecretKeySpec(this.key.getAesKey().toByteArray(InsecureSecretKeyAccess.get()), "AES"));

    // Generate subkeys; https://tools.ietf.org/html/rfc4493#section-2.3
    byte[] zeroes = new byte[AesUtil.BLOCK_SIZE];
    // As per documentation, the cipher is good to use after doFinal():
    // https://docs.oracle.com/javase/7/docs/api/javax/crypto/Cipher.html#doFinal(byte[])
    byte[] l = aes.doFinal(zeroes);
    subKey1 = AesUtil.dbl(l);
    subKey2 = AesUtil.dbl(subKey1);

    localStash = ByteBuffer.allocate(AesUtil.BLOCK_SIZE);
    x = ByteBuffer.allocate(AesUtil.BLOCK_SIZE);
    y = ByteBuffer.allocate(AesUtil.BLOCK_SIZE);
  }

  private void munch(ByteBuffer data) throws GeneralSecurityException {
    y.rewind();
    x.rewind();
    Bytes.xor(/* output= */ y, /* x= */ x, /* y= */ data, AesUtil.BLOCK_SIZE);

    y.rewind();
    x.rewind();
    aes.doFinal(/* input= */ y, /* output= */ x);
  }

  @Override
  public void update(ByteBuffer data) throws GeneralSecurityException {
    if (finalized) {
      throw new IllegalStateException(
          "Can not update after computing the MAC tag. Please create a new object.");
    }

    if (localStash.remaining() != AesUtil.BLOCK_SIZE) {
      // Only copy data into the stash if there are existing leftovers.
      int bytesToCopy = min(localStash.remaining(), data.remaining());
      for (int i = 0; i < bytesToCopy; i++) {
        localStash.put(data.get());
      }
    }
    if (localStash.remaining() == 0 && data.remaining() > 0) {
      // Stash is full but there is more data.
      localStash.rewind();
      munch(localStash);
      localStash.rewind();
    }

    // Now, "stash is empty" OR "data is empty".

    // Now process directly from the rest of the input buffer.
    // NOTE: if there are exactly block_size bytes left, don't process yet. (may be last block)
    while (data.remaining() > AesUtil.BLOCK_SIZE) {
      munch(data);
    }

    // There is now {0 .. block size} data left,
    // stash is empty with the block size capacity
    // => we can safely stuff everything into stash.
    localStash.put(data);
  }

  @Override
  public byte[] computeMac() throws GeneralSecurityException {
    if (finalized) {
      throw new IllegalStateException(
          "Can not compute after computing the MAC tag. Please create a new object.");
    }
    if (key.getParameters().getVariant() == Variant.LEGACY) {
      update(ByteBuffer.wrap(FORMAT_VERSION));
    }
    finalized = true;

    byte[] mLast;
    if (localStash.remaining() > 0) {
      // An incomplete block or an empty input.
      byte[] lastChunkToPad = Arrays.copyOf(localStash.array(), localStash.position());
      mLast = Bytes.xor(AesUtil.cmacPad(lastChunkToPad), subKey2);
    } else {
      // Block is full (remaining() == 0).
      mLast = Bytes.xor(localStash.array(), 0, subKey1, 0, AesUtil.BLOCK_SIZE);
    }

    return Bytes.concat(
        key.getOutputPrefix().toByteArray(),
        Arrays.copyOf(
            aes.doFinal(Bytes.xor(mLast, x.array())),
            key.getParameters().getCryptographicTagSizeBytes()));
  }
}
