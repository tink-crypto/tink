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

package com.google.crypto.tink.hybrid.subtle;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.DeterministicAead;
import com.google.crypto.tink.testing.TestUtil.DummyAead;
import java.security.GeneralSecurityException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for AeadOrDaead */
@RunWith(JUnit4.class)
public final class AeadOrDaeadTest {

  static final byte[] TEST_BYTE_VECTOR = {0, 1, 2, 3, 4, 5, 6, 7};

  /** A dummy Deterministic Aead-implementation that just throws exception. */
  private static class DummyDeterministicAead implements DeterministicAead {
    public DummyDeterministicAead() {}

    @Override
    public byte[] encryptDeterministically(byte[] plaintext, byte[] aad)
        throws GeneralSecurityException {
      throw new GeneralSecurityException("dummy deterministic encrypt");
    }

    @Override
    public byte[] decryptDeterministically(byte[] ciphertext, byte[] aad)
        throws GeneralSecurityException {
      throw new GeneralSecurityException("dummy deterministic decrypt");
    }
  }

  @Test
  public void testWithAeadPrimitive() {
    AeadOrDaead aeadOrDaead = new AeadOrDaead(new DummyAead());

    // Test that encrypt and decrypt is called on the DummyAead.
    GeneralSecurityException thrown =
        assertThrows(
            GeneralSecurityException.class,
            () -> aeadOrDaead.encrypt(TEST_BYTE_VECTOR, TEST_BYTE_VECTOR));
    assertThat(thrown).hasMessageThat().contains("dummy");

    thrown =
        assertThrows(
            GeneralSecurityException.class,
            () -> aeadOrDaead.decrypt(TEST_BYTE_VECTOR, TEST_BYTE_VECTOR));
    assertThat(thrown).hasMessageThat().contains("dummy");
  }

  @Test
  public void testWithDeterministicAeadPrimitive() {
    AeadOrDaead aeadOrDaead = new AeadOrDaead(new DummyDeterministicAead());

    // Test that encrypt and decrypt is called on the DummyDeterministicAead.
    GeneralSecurityException thrown =
        assertThrows(
            GeneralSecurityException.class,
            () -> aeadOrDaead.encrypt(TEST_BYTE_VECTOR, TEST_BYTE_VECTOR));
    assertThat(thrown).hasMessageThat().contains("dummy deterministic encrypt");

    thrown =
        assertThrows(
            GeneralSecurityException.class,
            () -> aeadOrDaead.decrypt(TEST_BYTE_VECTOR, TEST_BYTE_VECTOR));
    assertThat(thrown).hasMessageThat().contains("dummy deterministic decrypt");
  }
}
