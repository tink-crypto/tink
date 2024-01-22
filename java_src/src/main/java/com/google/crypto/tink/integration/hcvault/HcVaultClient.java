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

import com.google.auto.service.AutoService;
import com.google.crypto.tink.Aead;
import com.google.crypto.tink.KmsClient;
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import io.github.jopenlibs.vault.api.Logical;
import java.security.GeneralSecurityException;
import java.util.Locale;
import javax.annotation.Nullable;

/**
 * An implementation of {@link KmsClient} for <a href="https://www.vaultproject.io/">Hashicorp
 * Vault</a>.
 */
@AutoService(KmsClient.class)
public final class HcVaultClient implements KmsClient {
  /** The prefix of all keys stored in Hashicorp Vault. */
  public static final String PREFIX = "hcvault://";

  private static final String HTTP_PREFIX = "http://";
  private static final String HTTPS_PREFIX = "https://";

  private final Logical hcVault;
  @Nullable private final String keyUri;

  private HcVaultClient(Logical hcVault, String keyUri) {
    if (keyUri != null && !keyUri.toLowerCase(Locale.US).startsWith(PREFIX)) {
      throw new IllegalArgumentException("key URI must start with " + PREFIX);
    }
    this.hcVault = hcVault;
    this.keyUri = keyUri;
  }

  /**
   * @return true either if this client is a generic one and uri starts with {@link
   *     HcVaultClient#PREFIX}, or the client is a specific one that is bound to the key identified
   *     by {@code uri}.
   */
  @Override
  public boolean doesSupport(String uri) {
    if (this.keyUri != null && this.keyUri.equals(uri)) {
      return true;
    }
    return this.keyUri == null && uri.toLowerCase(Locale.US).startsWith(PREFIX);
  }

  @Override
  @CanIgnoreReturnValue
  public KmsClient withCredentials(String credentialPath) throws GeneralSecurityException {
    throw new UnsupportedOperationException(
        "HcVaultClient does not support loading credentials from a file");
  }

  @Override
  @CanIgnoreReturnValue
  public KmsClient withDefaultCredentials() throws GeneralSecurityException {
    throw new UnsupportedOperationException(
        "HcVaultClient does not support loading from default credentials");
  }

  /** Constructs a HcVaultClient that is not bound to a key URI. */
  public static KmsClient create(Logical hcVault) throws GeneralSecurityException {
    return new HcVaultClient(hcVault, null);
  }

  /** Constructs a HcVaultClient that is bound to a single key identified by {@code keyUri}. */
  public static KmsClient create(Logical hcVault, String keyUri) throws GeneralSecurityException {
    return new HcVaultClient(hcVault, keyUri);
  }

  @Override
  public Aead getAead(String uri) throws GeneralSecurityException {
    if (this.keyUri != null && !this.keyUri.equals(uri)) {
      throw new GeneralSecurityException(
          String.format(
              "this client is bound to %s, cannot load keys bound to %s", this.keyUri, uri));
    }

    try {
      return new HcVaultAead(this.hcVault, uri);
    } catch (Exception e) {
      throw new GeneralSecurityException("cannot load credentials from provider", e);
    }
  }
}
