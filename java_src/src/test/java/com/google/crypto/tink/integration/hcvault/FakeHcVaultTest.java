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
package com.google.crypto.tink.integration.hcvault;

import static com.google.common.truth.Truth.assertThat;
import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Arrays.asList;
import static org.junit.Assert.assertThrows;
import io.github.jopenlibs.vault.VaultException;
import io.github.jopenlibs.vault.api.Logical;
import io.github.jopenlibs.vault.response.LogicalResponse;
import com.google.crypto.tink.integration.hcvault.HcVaultAead;
import com.google.crypto.tink.aead.AeadConfig;
import java.nio.ByteBuffer;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class FakeHcVaultTest {

  private static final String KEY_URI = "hcvault://hcvault.corp.com:8200/transit/keys/key-1";
  private static final String KEY_URI_2 = "hcvault://hcvault.corp.com:8200/transit/keys/key-2";
  private static final String INVALID_KEY = "hcvaul://hcvault.corp.com:8200/transit/keys/invalid";

  @BeforeClass
  public static void setUpClass() throws Exception {
    AeadConfig.register();
  }

  @Test
  public void testEncryptDecryptWithValidKeyId_success() throws Exception {
    Logical kms = FakeHcVault.fromURI(KEY_URI);

    byte[] plaintext = "plaintext1".getBytes(UTF_8);
    byte[] associatedData = "associatedData".getBytes(UTF_8);

    String encPath = HcVaultAead.getOperationEndpoint(KEY_URI, "encrypt");
    String decPath = HcVaultAead.getOperationEndpoint(KEY_URI, "decrypt");
    Map<String,Object> content = new HashMap<>();
    content.put("plaintext", Base64.getEncoder().encodeToString(plaintext));
    content.put("context", Base64.getEncoder().encodeToString(associatedData));
    LogicalResponse encResp = kms.write(encPath, content);

    Map<String, String> encData = encResp.getData();
    Map<String, Object> decReq = new HashMap<>();
    decReq.put("context", Base64.getEncoder().encodeToString(associatedData));
    decReq.put("ciphertext", encResp.getData().get("ciphertext"));
    LogicalResponse decResp = kms.write(decPath, decReq);

    assertThat(Base64.getDecoder().decode(decResp.getData().get("plaintext"))).isEqualTo(plaintext);
  }
}
