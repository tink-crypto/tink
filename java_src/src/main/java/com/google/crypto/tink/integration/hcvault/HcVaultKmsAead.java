package com.google.crypto.tink.integration.hcvault;

import com.bettercloud.vault.api.Logical;
import com.bettercloud.vault.response.LogicalResponse;
import com.bettercloud.vault.Vault;
import com.bettercloud.vault.VaultException;
import com.google.crypto.tink.Aead;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Base64;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * A {@link Aead} that forwards encryption/decryption requests to a key in <a
 * href="https://www.vaultproject.io/docs/secrets/transit">Vault Transit Secrets Engine</a>.
 */
public class HcVaultKmsAead implements Aead {
  private final Vault vault;
  private final String encryptPath;
  private final String decryptPath;
  private final Pattern pattern = Pattern.compile("^/*([a-zA-Z0-9.:]+)/(.*)$");


  public HcVaultKmsAead(Vault vault, String keyUri) throws GeneralSecurityException {
    this.vault = vault;
    this.encryptPath = getEncryptPath(keyUri);
    this.decryptPath = getDecryptionPath(keyUri);
  }

  private String getDecryptionPath(String keyUri) throws GeneralSecurityException {
    String key = extractKey(keyUri);
    String[] parts = key.split("/");
    parts[parts.length - 2] = "decrypt";
    return String.join("/", parts);
  }

  private String getEncryptPath(String keyUri) throws GeneralSecurityException {
    String key = extractKey(keyUri);
    String[] parts = key.split("/");
    parts[parts.length - 2] = "encrypt";
    return String.join("/", parts);
  }

  private String extractKey(String keyUri) throws GeneralSecurityException {
    Matcher m = pattern.matcher(keyUri);

    if(!m.find()) {
      throw new GeneralSecurityException("malformed keyUri");
    }

    return m.group(2);
  }

  @Override
  public byte[] encrypt(byte[] plaintext, byte[] associatedData) throws GeneralSecurityException {
    Map<String, Object> request = Map.of(
        "plaintext", Base64.getEncoder().encodeToString(plaintext),
        "context", associatedData == null ? "" : Base64.getEncoder().encodeToString(associatedData)
    );

    try {
      LogicalResponse response = this.vault.logical().write(this.encryptPath, request);
      Map<String, String> data = response.getData();
      String error = data.get("errors");
      if (error != null) {
        throw new GeneralSecurityException("failed to encrypt");
      }

      String ciphertext = data.get("ciphertext");
      if (ciphertext == null) {
        throw new GeneralSecurityException("encryption failed");
      }
      return ciphertext.getBytes();
    } catch (VaultException e) {
      throw new GeneralSecurityException("vault error");
    }
  }

  @Override
  public byte[] decrypt(byte[] ciphertext, byte[] associatedData) throws GeneralSecurityException {
    Map<String, Object> request = Map.of(
        "ciphertext", new String(ciphertext, StandardCharsets.UTF_8),
        "context", associatedData == null ? "" : Base64.getEncoder().encodeToString(associatedData)
    );

    try {
      LogicalResponse response = this.vault.logical().write(this.decryptPath, request);
      Map<String, String> data = response.getData();
      String error = data.get("errors");
      if (error != null) {
        throw new GeneralSecurityException("failed to decrypt");
      }

      String plaintext64 = response.getData().get("plaintext");
      if (plaintext64 == null) {
        throw new GeneralSecurityException("decryption failed");
      }
      return Base64.getDecoder().decode(plaintext64);

    } catch (VaultException e) {
      throw new GeneralSecurityException("vault error");
    }
  }
}
