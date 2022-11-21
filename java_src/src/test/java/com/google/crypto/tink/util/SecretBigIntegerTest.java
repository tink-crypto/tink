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

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.InsecureSecretKeyAccess;
import java.math.BigInteger;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for {@link SecretBigInteger}. */
@RunWith(JUnit4.class)
public final class SecretBigIntegerTest {
  @Test
  public void fromBigIntegerToBigInteger_sameValue() throws Exception {
    BigInteger value = new BigInteger("1234567");
    SecretBigInteger secretValue =
        SecretBigInteger.fromBigInteger(value, InsecureSecretKeyAccess.get());
    assertThat(secretValue.getBigInteger(InsecureSecretKeyAccess.get())).isEqualTo(value);
  }

  @Test
  public void fromBigIntegerWithoutSecretAccess_throws() throws Exception {
    BigInteger value = new BigInteger("1234567");
    assertThrows(NullPointerException.class, () -> SecretBigInteger.fromBigInteger(value, null));
  }

  @Test
  public void getBigIntegerWithoutSecretAccess_throws() throws Exception {
    SecretBigInteger secretValue =
        SecretBigInteger.fromBigInteger(new BigInteger("1234567"), InsecureSecretKeyAccess.get());
    assertThrows(NullPointerException.class, () -> secretValue.getBigInteger(null));
  }

  @Test
  public void equalsSecretBigInteger() throws Exception {
    SecretBigInteger value =
        SecretBigInteger.fromBigInteger(new BigInteger("1234567"), InsecureSecretKeyAccess.get());
    SecretBigInteger sameValue =
        SecretBigInteger.fromBigInteger(new BigInteger("1234567"), InsecureSecretKeyAccess.get());
    SecretBigInteger otherValue =
        SecretBigInteger.fromBigInteger(new BigInteger("1234568"), InsecureSecretKeyAccess.get());
    SecretBigInteger otherValueWithDifferentLength =
        SecretBigInteger.fromBigInteger(new BigInteger("123456789"), InsecureSecretKeyAccess.get());

    assertThat(value.equalsSecretBigInteger(sameValue)).isTrue();
    assertThat(value.equalsSecretBigInteger(otherValue)).isFalse();
    assertThat(value.equalsSecretBigInteger(otherValueWithDifferentLength)).isFalse();
  }
}
