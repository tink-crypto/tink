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

package com.google.crypto.tink.subtle;

import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.prf.Prf;
import com.google.errorprone.annotations.Immutable;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * An implementation of CMAC following <a href="https://tools.ietf.org/html/rfc4493">RFC 4493</a>.
 */
@Immutable
public final class PrfAesCmac implements Prf {
  public static final TinkFipsUtil.AlgorithmFipsCompatibility FIPS =
      TinkFipsUtil.AlgorithmFipsCompatibility.ALGORITHM_NOT_FIPS;

  @SuppressWarnings("Immutable")
  private final SecretKey keySpec;

  @SuppressWarnings("Immutable")
  private byte[] subKey1;

  @SuppressWarnings("Immutable")
  private byte[] subKey2;

  private static Cipher instance() throws GeneralSecurityException {
    if (!FIPS.isCompatible()) {
      throw new GeneralSecurityException("Can not use AES-CMAC in FIPS-mode.");
    }
    return EngineFactory.CIPHER.getInstance("AES/ECB/NoPadding");
  }

  public PrfAesCmac(final byte[] key) throws GeneralSecurityException {
    Validators.validateAesKeySize(key.length);

    keySpec = new SecretKeySpec(key, "AES");
    generateSubKeys();
  }

  // https://tools.ietf.org/html/rfc4493#section-2.4
  @Override
  public byte[] compute(final byte[] data, int outputLength) throws GeneralSecurityException {
    if (outputLength > AesUtil.BLOCK_SIZE) {
      throw new InvalidAlgorithmParameterException(
          "outputLength too large, max is " + AesUtil.BLOCK_SIZE + " bytes");
    }
    Cipher aes = instance();
    aes.init(Cipher.ENCRYPT_MODE, keySpec);

    // n is the number of blocks (including partial blocks) into which the data
    // is divided. Empty data is divided into 1 empty block.
    // Step 2: n = ceil(length / blocksize)
    // TODO(b/68969256): Adding a test that computes a CMAC of length 2**31-1.
    int n = Math.max(1, (int) Math.ceil((double) data.length / AesUtil.BLOCK_SIZE));

    // Step 3
    boolean flag = (n * AesUtil.BLOCK_SIZE == data.length);

    // Step 4
    byte[] mLast;
    if (flag) {
      mLast = Bytes.xor(data, (n - 1) * AesUtil.BLOCK_SIZE, subKey1, 0, AesUtil.BLOCK_SIZE);
    } else {
      mLast =
          Bytes.xor(
              AesUtil.cmacPad(Arrays.copyOfRange(data, (n - 1) * AesUtil.BLOCK_SIZE, data.length)),
              subKey2);
    }

    // Step 5
    byte[] x = new byte[AesUtil.BLOCK_SIZE];

    // Step 6
    byte[] y;
    for (int i = 0; i < n - 1; i++) {
      y = Bytes.xor(x, 0, data, i * AesUtil.BLOCK_SIZE, AesUtil.BLOCK_SIZE);
      x = aes.doFinal(y);
    }
    y = Bytes.xor(mLast, x);

    // Step 7
    byte[] output = Arrays.copyOf(aes.doFinal(y), outputLength);
    return output;
  }

  // https://tools.ietf.org/html/rfc4493#section-2.3
  private void generateSubKeys() throws GeneralSecurityException {
    Cipher aes = instance();
    aes.init(Cipher.ENCRYPT_MODE, keySpec);
    byte[] zeroes = new byte[AesUtil.BLOCK_SIZE];
    byte[] l = aes.doFinal(zeroes);
    subKey1 = AesUtil.dbl(l);
    subKey2 = AesUtil.dbl(subKey1);
  }
}
