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

package com.google.crypto.tink.integration.hcvault;

import com.google.auto.service.AutoService;
import com.google.common.base.Splitter;
import com.google.crypto.tink.Aead;
import com.google.crypto.tink.KmsClient;
import com.google.crypto.tink.KmsClients;
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import io.github.jopenlibs.vault.*;
import io.github.jopenlibs.vault.api.Logical;
import java.security.GeneralSecurityException;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import javax.annotation.Nullable;

/**
 * An implementation of {@link KmsClient} for <a href="https://www.vaultproject.io/">Hashicorp Vault</a>.
 *
 * @since 1.0.0
 */
@AutoService(KmsClient.class)
public final class HcVaultClient implements KmsClient {
  /** The prefix of all keys stored in Hashicorp Vault. */
  public static final String PREFIX = "hcvault://";

  @Nullable private Logical hcVault;
  private String keyUri;
  @Nullable private VaultConfig vaultConf;
  private String authToken;
  private String namespace;
  private boolean https;
  private boolean verify;
  private String clientKeyPath;
  private String clientPemPath;

  /**
   * Constructs a generic HcVaultClient that is not bound to any specific key.
   *
   * This constructor should not be used. We recommend to register the client instead.
   */
  public HcVaultClient() {}

  /**
   * Constructs a specific HcVaultClient that is bound to a single key identified by {@code uri}.
   *
   * This constructor should not be used. We recommend to register the client instead.
   */
  public HcVaultClient(String uri) {
    if (!uri.toLowerCase(Locale.US).startsWith(PREFIX)) {
      throw new IllegalArgumentException("key URI must starts with " + PREFIX);
    }
    this.keyUri = uri;
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

  /**
   * Loads Hashicorp Vault credentials from a properties file.
   *
   * <p>The Hashicorp Vault token is expected to be in the <code>token</code> property.</p>
   *
   * @throws GeneralSecurityException if the client initialization fails
   */
  @Override
  @CanIgnoreReturnValue
  public KmsClient withCredentials(String credentialPath) throws GeneralSecurityException {
    try {
      throw new VaultException("cannot load credentials from path - not supported");
    } catch (VaultException e) {
      throw new GeneralSecurityException("cannot load credentials", e);
    }
  }

  /**
   * Loads default Hashicorp Vault credentials.
   *
   * <p>Hashicorp Vault credentials provider chain that looks for credentials in this order:
   *
   * <ul>
   *   <li>Environment Variables - VAULT_TOKEN and VAULT_URI
   *   <li>Java System Properties - hcvault.token and hcvault.uri
   *   <li>Filesystem - $user.home/.vault.token
   * </ul>
   *
   * @throws GeneralSecurityException if the client initialization fails
   */
  @Override
  @CanIgnoreReturnValue
  public KmsClient withDefaultCredentials() throws GeneralSecurityException {
    try {
      EnvironmentLoader envLoader = new EnvironmentLoader();
      String authToken = envLoader.loadVariable("VAULT_TOKEN");
      String keyUri = envLoader.loadVariable("VAULT_URI");
      String namespace = envLoader.loadVariable("VAULT_NAMESPACE");
      boolean https = Boolean.valueOf(envLoader.loadVariable("VAULT_HTTPS"));
      boolean verifyCert = Boolean.valueOf(envLoader.loadVariable("VAULT_VERIFY_CERT"));
      String clientPemPath = envLoader.loadVariable("VAULT_CLIENT_PEM");
      String clientKeyPath = envLoader.loadVariable("VAULT_CLIENT_KEY");
      VaultConfig config = new VaultConfig().address(keyUri)
                                            .token(authToken)
                                            .readTimeout(30)
                                            .openTimeout(30)
                                            .engineVersion(2);

      if (https) {
        config = config.sslConfig(new SslConfig().verify(verifyCert));
      }

      if (namespace != null) {
        config = config.nameSpace(namespace);
      }

      this.vaultConf = config.build();
      this.hcVault = Vault.create(vaultConf).logical();
      return this;
    } catch (VaultException e) {
      throw new GeneralSecurityException("error loading default credentials", e);
    }
  }

  /** Loads Hashicorp Vault credentials from a provider. */
  @CanIgnoreReturnValue
  public KmsClient withCredentialsProvider(VaultConfig vaultConf)
      throws GeneralSecurityException {
    this.vaultConf = vaultConf;
    return this;
  }

  /**
   * Specifies the {@link Logical} object to be used. Only used for
   * testing.
   */
  @CanIgnoreReturnValue
  KmsClient withHcVault(@Nullable Logical hcVault) {
    this.hcVault = hcVault;
    return this;
  }

  @Override
  public Aead getAead(String uri) throws GeneralSecurityException {
    if (this.keyUri != null && !this.keyUri.equals(uri)) {
      throw new GeneralSecurityException(
          String.format(
              "this client is bound to %s, cannot load keys bound to %s", this.keyUri, uri));
    }

    try {
      Logical client = hcVault;
      if (client == null) {
        Vault v = Vault.create(this.vaultConf);
        client = v.logical();
      }
      return new HcVaultAead(client, this.keyUri);
    } catch (Exception e) {
      throw new GeneralSecurityException("cannot load credentials from provider", e);
    }
  }

  /**
   * Creates and registers a {@link #HcVaultClient} with the Tink runtime.
   *
   * <p>If {@code keyUri} is present, it is the only key that the new client will support. Otherwise
   * the new client supports all Hashicorp Vault keys.
   *
   * <p>If {@code authToken} is present, use that for authentication. Otherwise, use the "default" 
   * credentials.
   */
  public static void register(String keyUri, String authToken)
      throws GeneralSecurityException {
    registerWithHcVault(keyUri, authToken, null, true, true, Optional.empty());
  }

    /**
   * Creates and registers a {@link #HcVaultClient} with the Tink runtime.
   *
   * <p>If {@code keyUri} is present, it is the only key that the new client will support. Otherwise
   * the new client supports all Hashicorp Vault keys.
   *
   * <p>If {@code authToken} is present, use that for authentication. Otherwise, use the "default" 
   * credentials.
   */
  public static void register(String keyUri, String authToken, boolean https, 
      boolean verifyCert, Optional<String> namespace)
      throws GeneralSecurityException {
    registerWithHcVault(keyUri, authToken, null, https, verifyCert, namespace);
  }

  /**
   * Does the same as {@link #register}, but with an additional {@code hcVault} argument. Only used
   * for testing.
   */
  static void registerWithHcVault(
      String keyUri, String authToken, @Nullable Logical hcVault, boolean https, 
      boolean verifyCert, Optional<String> namespace)
      throws GeneralSecurityException {
    try {
      HcVaultClient client = new HcVaultClient(keyUri);

      VaultConfig config = new VaultConfig().address(keyUri)
                                            .token(authToken)
                                            .readTimeout(30)
                                            .openTimeout(30)
                                            .engineVersion(2);

      if (https) {
        config = config.sslConfig(new SslConfig().verify(verifyCert));
      }

      if (namespace.isPresent()) {
        config = config.nameSpace(namespace.get());
      }

      config = config.build();

      if (hcVault == null) {
        hcVault = Vault.create(config).logical();
      }

      client.withCredentialsProvider(config);
      client.withHcVault(hcVault);
      KmsClients.add(client);
    } catch (VaultException e) {
      throw new GeneralSecurityException("failed to create client", e);
    }
  }
}
