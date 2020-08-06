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

/**
 * A {@link Aead} that forwards encryption/decryption requests to a key in <a
 * href="https://www.vaultproject.io/docs/secrets/transit">Vault Transit Secrets Engine</a>.
 */
public class HcVaultKmsAead implements Aead {
  private final Vault vault;
  private final String encryptPath;
  private final String decryptPath;


  public HcVaultKmsAead(Vault vault, String keyUri) {
    this.vault = vault;
    this.encryptPath = PathBuilder.encryptionPath(keyUri);
    this.decryptPath = PathBuilder.decryptionPath(keyUri);
  }

  private static class PathBuilder {
    private static String buildPath(String keyUri, String action) {
      String[] parts = keyUri.split("/");
      parts[parts.length - 2] = action;
      return String.join("/", parts);
    }

    private static String encryptionPath(String keyUri) {
      return buildPath(keyUri, "encrypt");
    }

    private static String decryptionPath(String keyUri) {
      return buildPath(keyUri, "decrypt");
    }
  }

  @Override
  public byte[] encrypt(byte[] plaintext, byte[] associatedData) throws GeneralSecurityException {
    if (this.encryptPath == null || this.encryptPath.equals("")) {
      throw new GeneralSecurityException("malformed keyUri provided");
    }

    Map<String, Object> request = Map.of(
        "plaintext", Base64.getEncoder().encodeToString(plaintext),
        "context", associatedData == null ? "" : Base64.getEncoder().encodeToString(associatedData)
    );

    try {
      LogicalResponse response = this.vault.logical().write(this.encryptPath, request);
      Map<String, String> data = response.getData();
      String error = data.get("errors");
      if (error != null) {
        throw new GeneralSecurityException(String.format("Failed to encrypt: %s", error));
      }

      String ciphertext = data.get("ciphertext");
      if (ciphertext == null) {
        throw new GeneralSecurityException("encryption failed");
      }
      return ciphertext.getBytes();
    } catch (VaultException e) {
      throw new GeneralSecurityException("vault error", e);
    }
  }

  @Override
  public byte[] decrypt(byte[] ciphertext, byte[] associatedData) throws GeneralSecurityException {
    if (this.decryptPath == null || this.decryptPath.equals("")) {
      throw new GeneralSecurityException("malformed keyUri provided");
    }

    Map<String, Object> request = Map.of(
        "ciphertext", new String(ciphertext, StandardCharsets.UTF_8),
        "context", associatedData == null ? "" : Base64.getEncoder().encodeToString(associatedData)
    );

    try {
      LogicalResponse response = this.vault.logical().write(this.decryptPath, request);
      Map<String, String> data = response.getData();
      String error = data.get("errors");
      if (error != null) {
        throw new GeneralSecurityException(String.format("Failed to decrypt: %s", error));
      }

      String plaintext64 = response.getData().get("plaintext");
      if (plaintext64 == null) {
        throw new GeneralSecurityException("decryption failed");
      }
      return Base64.getDecoder().decode(plaintext64);

    } catch (VaultException e) {
      throw new GeneralSecurityException("decryption failed", e);
    }
  }
}
