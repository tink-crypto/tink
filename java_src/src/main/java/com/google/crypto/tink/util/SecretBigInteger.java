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

package com.google.crypto.tink.util;

import com.google.crypto.tink.SecretKeyAccess;
import com.google.errorprone.annotations.Immutable;
import java.math.BigInteger;
import java.security.MessageDigest;

/** A class storing a secret BigInteger, protecting the value via {@link SecretKeyAccess}. */
@Immutable
public final class SecretBigInteger {
  private final BigInteger value;

  private SecretBigInteger(BigInteger value) {
    this.value = value;
  }

  /**
   * Creates a new SecretBigInteger with the content given in {@code value}.
   *
   * <p>The parameter {@code access} must be non-null.
   */
  public static SecretBigInteger fromBigInteger(BigInteger value, SecretKeyAccess access) {
    if (access == null) {
      throw new NullPointerException("SecretKeyAccess required");
    }
    // Since BigInteger is immutable, there is no need to make a copy.
    return new SecretBigInteger(value);
  }

  /**
   * Returns the value wrapped by this object.
   *
   * <p>The parameter {@code access} must be non-null.
   */
  public BigInteger getBigInteger(SecretKeyAccess access) {
    if (access == null) {
      throw new NullPointerException("SecretKeyAccess required");
    }
    return value;
  }

  /**
   * Returns true if {@code other} has the same secret value.
   *
   * <p>Note that the time may depend on the length of the byte-encoding of the BigIntegers.
   */
  public boolean equalsSecretBigInteger(SecretBigInteger other) {
    // BigInteger.toByteArray always return the minimal encoding, so it is not possible that two
    // BigInteger of the same values return different encodings.
    byte[] myArray = value.toByteArray();
    byte[] otherArray = other.value.toByteArray();
    return MessageDigest.isEqual(myArray, otherArray);
  }
}
