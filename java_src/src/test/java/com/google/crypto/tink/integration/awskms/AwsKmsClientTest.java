// Copyright 2021 Google LLC
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

package com.google.crypto.tink.integration.awskms;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.KmsClient;
import com.google.crypto.tink.KmsClients;
import com.google.crypto.tink.KmsClientsTestUtil;
import java.util.Optional;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for AwsKmsClient. */
@RunWith(JUnit4.class)
public final class AwsKmsClientTest {
  private static final String CREDENTIAL_FILE_PATH =
      "testdata/aws/credentials.cred";

  @Before
  public void setUp() {
    KmsClientsTestUtil.reset();
  }

  @Test
  public void register() throws Exception {
    // Register a client bound to a single key.
    String keyUri = "aws-kms://register";
    AwsKmsClient.register(Optional.of(keyUri), Optional.of(CREDENTIAL_FILE_PATH));

    KmsClient client = KmsClients.get(keyUri);
    assertThat(client.doesSupport(keyUri)).isTrue();

    String modifiedKeyUri = keyUri + "1";
    assertThat(client.doesSupport(modifiedKeyUri)).isFalse();
  }

  @Test
  public void register_unbound() throws Exception {
    // Register an unbound client.
    AwsKmsClient.register(Optional.empty(), Optional.of(CREDENTIAL_FILE_PATH));

    // This should return the above unbound client.
    String keyUri = "aws-kms://register-unbound";
    KmsClient client = KmsClients.get(keyUri);
    assertThat(client.doesSupport(keyUri)).isTrue();

    String modifiedKeyUri = keyUri + "1";
    assertThat(client.doesSupport(modifiedKeyUri)).isTrue();
  }

  @Test
  public void register_badKeyUri_fail() throws Exception {
    assertThrows(
        IllegalArgumentException.class,
        () -> AwsKmsClient.register(Optional.of("blah"), Optional.of(CREDENTIAL_FILE_PATH)));
  }
}
