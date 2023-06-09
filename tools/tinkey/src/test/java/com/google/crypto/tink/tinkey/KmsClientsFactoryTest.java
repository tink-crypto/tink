// Copyright 2023 Google LLC
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

package com.google.crypto.tink.tinkey;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import java.security.GeneralSecurityException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class KmsClientsFactoryTest {
  @Test
  public void testAddAndUse_works() throws Exception {
    KmsClientsFactory factory = new KmsClientsFactory();
    factory.addFactory(TinkeyTestKmsClient::new);

    assertThat(factory.newClientFor("tinkey-test-kms-client://some"))
        .isInstanceOf(TinkeyTestKmsClient.class);
  }

  @Test
  public void test_newInstances_differ() throws Exception {
    KmsClientsFactory factory = new KmsClientsFactory();
    factory.addFactory(TinkeyTestKmsClient::new);

    assertThat(factory.newClientFor("tinkey-test-kms-client://some"))
        .isNotEqualTo(factory.newClientFor("tinkey-test-kms-client://some"));
  }

  @Test
  public void test_notSupported_throws() throws Exception {
    KmsClientsFactory factory = new KmsClientsFactory();
    factory.addFactory(TinkeyTestKmsClient::new);

    assertThrows(
        GeneralSecurityException.class, () -> factory.newClientFor("not_supported://some"));
  }

  @Test
  public void test_multiplePrefixes_works() throws Exception {
    KmsClientsFactory factory = new KmsClientsFactory();
    factory.addFactory(() -> TinkeyTestKmsClient.createForPrefix("prefix1:"));
    factory.addFactory(() -> TinkeyTestKmsClient.createForPrefix("prefix2:"));

    assertThat(factory.newClientFor("prefix1:foo")).isInstanceOf(TinkeyTestKmsClient.class);
    assertThat(factory.newClientFor("prefix2:bar")).isInstanceOf(TinkeyTestKmsClient.class);
    assertThrows(GeneralSecurityException.class, () -> factory.newClientFor("prefix3://some"));
  }
}
