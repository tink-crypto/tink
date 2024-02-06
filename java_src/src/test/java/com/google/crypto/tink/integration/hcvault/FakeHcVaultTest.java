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
package com.google.crypto.tink.integration.hcvault;

import static com.google.common.truth.Truth.assertThat;
import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Arrays.asList;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.aead.AeadConfig;
import io.github.jopenlibs.vault.VaultException;
import io.github.jopenlibs.vault.api.Logical;
import io.github.jopenlibs.vault.response.LogicalResponse;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class FakeHcVaultTest {

  @BeforeClass
  public static void setUpClass() throws Exception {
    AeadConfig.register();
  }

  @Test
  public void testEncryptDecryptWithValidKeyId() throws Exception {
    Logical kms =
        new FakeHcVault(/* mountPath= */ "transit", /* validKeyNames= */ asList("key-1", "key-2"));

    byte[] plaintext = "plaintext1".getBytes(UTF_8);
    byte[] associatedData = "associatedData".getBytes(UTF_8);

    String encPath = "transit/encrypt/key-1";
    Map<String, Object> encReq = new HashMap<>();
    encReq.put("plaintext", Base64.getEncoder().encodeToString(plaintext));
    encReq.put("context", Base64.getEncoder().encodeToString(associatedData));
    LogicalResponse encResp = kms.write(encPath, encReq);

    String ciphertext = (String) encResp.getData().get("ciphertext");

    String decPath = "transit/decrypt/key-1";
    Map<String, Object> decReq = new HashMap<>();
    decReq.put("context", Base64.getEncoder().encodeToString(associatedData));
    decReq.put("ciphertext", ciphertext);
    LogicalResponse decResp = kms.write(decPath, decReq);

    assertThat(Base64.getDecoder().decode(decResp.getData().get("plaintext"))).isEqualTo(plaintext);

    // valid encResp with an invalid encrypt path fails.
    assertThrows(VaultException.class, () -> kms.write("transit/encrypt/invalid-key", encReq));
    assertThrows(VaultException.class, () -> kms.write("invalid/encrypt/key-1", encReq));

    // valid decReq with a valid path of different key fails.
    assertThrows(VaultException.class, () -> kms.write("transit/decrypt/key-2", decReq));

    // valid decReq with an invalid decrypt path fails.
    assertThrows(VaultException.class, () -> kms.write("transit/decrypt/invalid-key", decReq));
    assertThrows(VaultException.class, () -> kms.write("invalid/decrypt/key-1", decReq));

    // valid decPath with an invalid decrypt request fails.
    Map<String, Object> invalidDecReq = new HashMap<>();
    invalidDecReq.put("context", Base64.getEncoder().encodeToString(associatedData));
    invalidDecReq.put("ciphertext", "invalid");
    assertThrows(VaultException.class, () -> kms.write(decPath, invalidDecReq));

    // valid request with invalid path fails.
    assertThrows(VaultException.class, () -> kms.write("invalid/path", encReq));
    assertThrows(VaultException.class, () -> kms.write("invalid/path", decReq));
  }
}
