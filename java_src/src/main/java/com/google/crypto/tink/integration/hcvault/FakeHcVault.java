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

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.KeyTemplates;
import com.google.crypto.tink.KeysetHandle;
import io.github.jopenlibs.vault.VaultConfig;
import io.github.jopenlibs.vault.VaultException;
import io.github.jopenlibs.vault.api.Logical;
import io.github.jopenlibs.vault.response.LogicalResponse;
import io.github.jopenlibs.vault.rest.RestResponse;
import java.nio.charset.Charset;
import java.security.GeneralSecurityException;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * A partial, fake implementation of Hashicorp Vault that only supports encrypt and decrypt.
 *
 * <p>It creates a new AEAD for every instance. It can only encrypt and decrypt keys for the URI
 * specified in the config.
 */
final class FakeHcVault extends Logical {
  private static final Charset UTF_8 = Charset.forName("UTF-8");
  private final String encPathPrefix;
  private final String decPathPrefix;
  private final Map<String, Aead> aeads = new HashMap<>();

  public FakeHcVault(String mountPath, List<String> validKeyNames) {
    super(
        new VaultConfig()
            .address("https://hcvault.corp.com:8200")
            .token(null)
            .readTimeout(30)
            .openTimeout(30)
            .engineVersion(2));
    this.encPathPrefix = mountPath + "/encrypt/";
    this.decPathPrefix = mountPath + "/decrypt/";
    try {
      for (String keyName : validKeyNames) {
        Aead aead =
            KeysetHandle.generateNew(KeyTemplates.get("AES128_GCM")).getPrimitive(Aead.class);
        aeads.put(keyName, aead);
      }
    } catch (GeneralSecurityException e) {
      throw new IllegalArgumentException(e);
    }
  }

  @Override
  public LogicalResponse write(final String path, final Map<String, Object> nameValuePairs)
      throws VaultException {
    if (path.startsWith(encPathPrefix)) {
      String keyName = path.substring(encPathPrefix.length());
      if (!aeads.containsKey(keyName)) {
        throw new VaultException("Key not found: " + keyName);
      }
      Aead aead = aeads.get(keyName);
      byte[] context = Base64.getDecoder().decode((String) nameValuePairs.get("context"));
      byte[] plaintext = Base64.getDecoder().decode((String) nameValuePairs.get("plaintext"));
      byte[] ciphertext;
      try {
        ciphertext = aead.encrypt(plaintext, context);
      } catch (GeneralSecurityException e) {
        throw new VaultException(e.getMessage());
      }
      RestResponse restResp = new RestResponse(200, null, null);
      LogicalResponse resp = new LogicalResponse(restResp, 0, null);
      resp.getData().put("ciphertext", new String(Base64.getEncoder().encode(ciphertext)));
      return resp;
    }
    if (path.startsWith(decPathPrefix)) {
      String keyName = path.substring(decPathPrefix.length());
      if (!aeads.containsKey(keyName)) {
        throw new VaultException("Key not found: " + keyName);
      }
      Aead aead = aeads.get(keyName);
      byte[] context = Base64.getDecoder().decode((String) nameValuePairs.get("context"));
      String ciphertext = (String) nameValuePairs.get("ciphertext");
      byte[] ciphertextBytes = Base64.getDecoder().decode(ciphertext);
      byte[] plaintext;
      try {
        plaintext = aead.decrypt(ciphertextBytes, context);
      } catch (GeneralSecurityException e) {
        throw new VaultException(e.getMessage());
      }
      RestResponse restResp = new RestResponse(200, null, null);
      LogicalResponse resp = new LogicalResponse(restResp, 0, null);
      resp.getData().put("plaintext", Base64.getEncoder().encodeToString(plaintext));
      return resp;
    }
    throw new VaultException("Unsupported path: " + path);
  }
}
