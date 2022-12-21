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

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.aead.AeadConfig;
import com.google.crypto.tink.subtle.Random;
import java.security.GeneralSecurityException;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for {@code FakeKmsClient}. */
@RunWith(JUnit4.class)
public final class FakeKmsClientTest {

  @Before
  public void setUp() throws GeneralSecurityException {
    AeadConfig.register();
  }

  @Test
  public void createNewAead_success() throws GeneralSecurityException {
    String uri = FakeKmsClient.createFakeKeyUri();
    FakeKmsClient client = new FakeKmsClient(uri);
    assertThat(client.doesSupport(uri)).isTrue();
    Aead aead = client.getAead(uri);

    byte[] plaintext = Random.randBytes(20);
    byte[] associatedData = Random.randBytes(20);
    byte[] ciphertext = aead.encrypt(plaintext, associatedData);
    assertArrayEquals(plaintext, aead.decrypt(ciphertext, associatedData));
  }

  @Test
  public void clientIsBound_rejectsOtherKey() throws GeneralSecurityException {
    String uri =
        "fake-kms://CIqphp8HEo0BCoABCjh0eXBlLmdvb2dsZWFwaXMuY29tL2dvb2dsZS5jcnlwdG8udGluay5B"
            + "ZXNDdHJIbWFjQWVhZEtleRJCEhYSAggQGhBBqhLL7pdFk-FzEYi4lo5CGigSBAgDEBAaIFRMn3OEi"
            + "QQKUb85xOdhmuqMmvderls5oymgmtSLYKabGAEQARiKqYafByAB";
    FakeKmsClient client = new FakeKmsClient(uri);
    assertThat(client.doesSupport(uri)).isTrue();
    Object unused = client.getAead(uri); // No exception

    // No other key_uri is accepted, even a valid one.
    String anotherUri =
        "fake-kms://CPeFs9sGEo0BCoABCjh0eXBlLmdvb2dsZWFwaXMuY29tL2dvb2dsZS5jcnlwdG8udGluay5B"
            + "ZXNDdHJIbWFjQWVhZEtleRJCEhYSAggQGhCE7VadpBOqUEib9Db55aI2GigSBAgDEBAaII0DdIzGe"
            + "3r2nXHnGoSRa9GZXGsjZsl719GfJrhtjjVGGAEQARj3hbPbBiAB";
    assertThat(client.doesSupport(anotherUri)).isFalse();
    assertThrows(GeneralSecurityException.class, () -> client.getAead(anotherUri));
  }

  @Test
  public void clientIsUnbound_acceptsKeys() throws GeneralSecurityException {
    FakeKmsClient client = new FakeKmsClient();

    String uri =
        "fake-kms://CIqphp8HEo0BCoABCjh0eXBlLmdvb2dsZWFwaXMuY29tL2dvb2dsZS5jcnlwdG8udGluay5B"
            + "ZXNDdHJIbWFjQWVhZEtleRJCEhYSAggQGhBBqhLL7pdFk-FzEYi4lo5CGigSBAgDEBAaIFRMn3OEi"
            + "QQKUb85xOdhmuqMmvderls5oymgmtSLYKabGAEQARiKqYafByAB";
    assertThat(client.doesSupport(uri)).isTrue();
    Object unused = client.getAead(uri); // No exception
    String anotherUri =
        "fake-kms://CPeFs9sGEo0BCoABCjh0eXBlLmdvb2dsZWFwaXMuY29tL2dvb2dsZS5jcnlwdG8udGluay5B"
            + "ZXNDdHJIbWFjQWVhZEtleRJCEhYSAggQGhCE7VadpBOqUEib9Db55aI2GigSBAgDEBAaII0DdIzGe"
            + "3r2nXHnGoSRa9GZXGsjZsl719GfJrhtjjVGGAEQARj3hbPbBiAB";
    assertThat(client.doesSupport(anotherUri)).isTrue();
    unused = client.getAead(anotherUri); // No exception
  }
}
