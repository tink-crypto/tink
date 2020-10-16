package com.google.crypto.tink.integration.hcvault;

import com.bettercloud.vault.Vault;
import com.bettercloud.vault.VaultConfig;
import com.bettercloud.vault.VaultException;
import com.google.auto.service.AutoService;
import com.google.crypto.tink.Aead;
import com.google.crypto.tink.KmsClient;
import com.google.crypto.tink.subtle.Validators;

import java.net.URI;
import java.net.URISyntaxException;
import java.security.GeneralSecurityException;

/**
 * An implementation of {@link KmsClient} for <a
 * href="https://www.vaultproject.io/docs/secrets/transit">Vault Transit Secrets Engine</a>..
 */
@AutoService(KmsClient.class)
public class HcVaultKmsClient implements KmsClient {
  public static final String PREFIX = "hcvault://";

  private String keyUri;
  private Vault vault;

  public HcVaultKmsClient() {}

  /** Constructs a specific HcVaultKmsClient that is bound to a single key identified by {@code uri}. */
  public HcVaultKmsClient(String uri) {
    if (!uri.toLowerCase().startsWith(PREFIX)) {
      throw new IllegalArgumentException("key URI must starts with " + PREFIX);
    }
    this.keyUri = uri;
  }

  /**
   * @return @return true either if this client is a generic one and uri starts with {@link
   * HcVaultKmsClient#PREFIX}, or the client is a specific one that is bound to the key identified
   * by {@code uri}.
   */
  @Override
  public boolean doesSupport(String uri) {
    if (this.keyUri != null && this.keyUri.equals(uri)) {
      return true;
    }
    return this.keyUri == null && uri.toLowerCase().startsWith(PREFIX);
  }

  /**
   * Loads Vault config with the provided {@code token}.
   *
   * <p>If {@code token} is null, loads token from "VAULT_TOKEN" environment variables.</p>
   * <p>
   * All other configuration elements will also be read from environment variables.
   */
  @Override
  public KmsClient withCredentials(String token) throws GeneralSecurityException {
    try {
      URI uri = new URI(this.keyUri);
      VaultConfig config = new VaultConfig()
              .address(uri.getHost())
              .token(token)
              .build();

      this.vault = new Vault(config);
      return this;
    } catch (URISyntaxException | VaultException e) {
      throw new GeneralSecurityException("invalid path provided");
    }
  }

  /**
   * Loads default Vault config.
   *
   * <p>Vault Address, Token and timeouts can be loaded from environment variables.
   *
   * <ul>
   *     <li>Vault Address read from "VAULT_ADDR" environment variable</li>
   *     <li>Vault Token read from "VAULT_TOKEN" environment variable</li>
   *     <li>Open Timeout read from "VAULT_OPEN_TIMEOUT" environment variable</li>
   *     <li>Read Timeout read from "VAULT_READ_TIMEOUT" environment variable</li>
   * </ul>
   * </p>
   */
  @Override
  public KmsClient withDefaultCredentials() throws GeneralSecurityException {
    try {
      URI uri = new URI(this.keyUri);
      this.vault = new Vault(new VaultConfig()
              .address(uri.getHost())
              .build());
    } catch (URISyntaxException | VaultException e) {
      throw new GeneralSecurityException("unable to create config");
    }
    return this;
  }

  /** Utilizes the provided vault client. */
  public KmsClient withVault(Vault vault) {
    this.vault = vault;
    return this;
  }

  @Override
  public Aead getAead(String uri) throws GeneralSecurityException {
    if (this.keyUri != null && !this.keyUri.equals(uri)) {
      throw new GeneralSecurityException(
          String.format(
              "this client is bound to %s, cannot load keys bound to %s", this.keyUri, uri));
    }

    return new HcVaultKmsAead(this.vault, Validators.validateKmsKeyUriAndRemovePrefix(PREFIX, uri));
  }
}
