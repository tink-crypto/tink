// Copyright 2020 Google LLC
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

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.Mac;
import com.google.crypto.tink.mac.AesCmacKey;
import com.google.crypto.tink.mac.AesCmacParameters.Variant;
import com.google.crypto.tink.mac.HmacKey;
import com.google.crypto.tink.mac.HmacParameters;
import com.google.crypto.tink.prf.Prf;
import com.google.errorprone.annotations.Immutable;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.util.Arrays;
import javax.crypto.spec.SecretKeySpec;

/**
 * Class that provides the functionality expressed by the Mac primitive using a Prf implementation.
 */
@Immutable
@AccessesPartialKey
public class PrfMac implements Mac {
  // A single byte to be added to the plaintext for the legacy key type.
  private static final byte[] FORMAT_VERSION = new byte[] {0};
  static final int MIN_TAG_SIZE_IN_BYTES = 10;

  private final Prf wrappedPrf;
  private final int tagSize;

  @SuppressWarnings("Immutable")
  private final byte[] outputPrefix;
  // A field that regulates whether we add a zero-byte to the plaintext or not (because of
  // the LEGACY variant).
  @SuppressWarnings("Immutable")
  private final byte[] plaintextLegacySuffix;

  /** Wrap {@code wrappedPrf } in a Mac primitive with the specified {@code tagSize} */
  public PrfMac(Prf wrappedPrf, int tagSize) throws GeneralSecurityException {
    this.wrappedPrf = wrappedPrf;
    this.tagSize = tagSize;
    this.outputPrefix = new byte[0];
    this.plaintextLegacySuffix = new byte[0];

    // The output length is restricted by the HMAC spec. Check that first.
    if (tagSize < MIN_TAG_SIZE_IN_BYTES) {
      throw new InvalidAlgorithmParameterException(
          "tag size too small, need at least " + MIN_TAG_SIZE_IN_BYTES + " bytes");
    }

    // Some Prf implementations have restrictions on maximum tag length. These throw on compute().
    // Check for those restrictions on tag length here by doing a compute() pass.
    Object unused = wrappedPrf.compute(new byte[0], tagSize);
  }

  private PrfMac(AesCmacKey key) throws GeneralSecurityException {
    wrappedPrf = new PrfAesCmac(key.getAesKey().toByteArray(InsecureSecretKeyAccess.get()));
    // Due to the correctness checks during AesCmacKey creation, there is no need to perform
    // additional tag size checks here.
    tagSize = key.getParameters().getCryptographicTagSizeBytes();
    outputPrefix = key.getOutputPrefix().toByteArray();
    if (key.getParameters().getVariant().equals(Variant.LEGACY)) {
      plaintextLegacySuffix = Arrays.copyOf(FORMAT_VERSION, FORMAT_VERSION.length);
    } else {
      plaintextLegacySuffix = new byte[0];
    }
  }

  private PrfMac(HmacKey key) throws GeneralSecurityException {
    // The use of toString() in this code leverages the fact that the constructor will not work if
    // the algorithm name is incorrect.
    wrappedPrf =
        new PrfHmacJce(
            "HMAC" + key.getParameters().getHashType(),
            new SecretKeySpec(
                key.getKeyBytes().toByteArray(InsecureSecretKeyAccess.get()), "HMAC"));
    // Due to the correctness checks during AesCmacKey creation, there is no need to perform
    // additional tag size checks here.
    tagSize = key.getParameters().getCryptographicTagSizeBytes();
    outputPrefix = key.getOutputPrefix().toByteArray();
    if (key.getParameters().getVariant().equals(HmacParameters.Variant.LEGACY)) {
      plaintextLegacySuffix = Arrays.copyOf(FORMAT_VERSION, FORMAT_VERSION.length);
    } else {
      plaintextLegacySuffix = new byte[0];
    }
  }

  /** Creates an object implementing the {@link Mac} interface using an AesCmac underneath. */
  public static Mac create(AesCmacKey key) throws GeneralSecurityException {
    return new PrfMac(key);
  }

  /** Creates an object implementing the {@link Mac} interface using an Hmac underneath. */
  public static Mac create(HmacKey key) throws GeneralSecurityException {
    return new PrfMac(key);
  }

  @Override
  public byte[] computeMac(byte[] data) throws GeneralSecurityException {
    if (plaintextLegacySuffix.length > 0) {
      return Bytes.concat(
          outputPrefix, wrappedPrf.compute(Bytes.concat(data, plaintextLegacySuffix), tagSize));
    }
    return Bytes.concat(outputPrefix, wrappedPrf.compute(data, tagSize));
  }

  @Override
  public void verifyMac(byte[] mac, byte[] data) throws GeneralSecurityException {
    if (!Bytes.equal(computeMac(data), mac)) {
      throw new GeneralSecurityException("invalid MAC");
    }
  }
}
