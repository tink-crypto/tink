package com.google.crypto.tink.integration.hcvault;


import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.fail;
import static org.mockito.ArgumentMatchers.isA;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.when;

import com.bettercloud.vault.response.LogicalResponse;
import com.bettercloud.vault.api.Logical;
import com.bettercloud.vault.Vault;
import com.bettercloud.vault.VaultException;
import com.google.crypto.tink.Aead;
import com.google.crypto.tink.subtle.Random;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

@RunWith(MockitoJUnitRunner.class)
public class HcVaultKmsAeadTest {
  public static final String uri = "transit/keys/key-1";
  public static final String encrypt = "transit/encrypt/key-1";
  public static final String decrypt = "transit/decrypt/key-1";
  @Mock
  private Vault mockKms;

  @Mock
  private Logical mockLogical;

  @Mock
  private LogicalResponse mockDecryptResponse;

  @Mock
  private LogicalResponse mockEncryptResponse;

  @Before
  public void setUp() throws Exception {
    when(mockKms.logical()).thenReturn(mockLogical);
  }

  @Test
  public void testEncryptDecrypt() throws Exception {
    Aead aead = new HcVaultKmsAead(mockKms, uri);

    when(mockLogical.write(eq(encrypt), any())).thenReturn(mockEncryptResponse);
    when(mockLogical.write(eq(decrypt), any())).thenReturn(mockDecryptResponse);

    byte[] aad = Random.randBytes(20);
    for (int messageSize = 0; messageSize < 75; messageSize++) {
      byte[] message = Random.randBytes(messageSize);
      String m = new String(message, StandardCharsets.UTF_8);

      Map<String, String> responses = new HashMap<String, String>(
          Map.of(
              "plaintext", Base64.getEncoder().encodeToString(message),
              "ciphertext", m
          ));

      when(mockEncryptResponse.getData()).thenReturn(responses);
      when(mockDecryptResponse.getData()).thenReturn(responses);

      byte[] ciphertext = aead.encrypt(message, aad);
      byte[] decrypted = aead.decrypt(ciphertext, aad);

      assertArrayEquals(message, decrypted);
    }
  }

  @Test
  public void testEncryptShouldThrowExceptionIfRequestFailed() throws Exception {
    VaultException exception = mock(VaultException.class);
    when(mockLogical.write(eq(encrypt), any())).thenThrow(exception);

    Aead aead = new HcVaultKmsAead(mockKms, uri);
    byte[] aad = Random.randBytes(20);
    byte[] message = Random.randBytes(20);
    try {
      aead.encrypt(message, aad);
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      // expected.
    }
  }

  @Test
  public void testDecryptShouldThrowExceptionIfRequestFailed() throws Exception {
    VaultException exception = mock(VaultException.class);
    when(mockLogical.write(eq(decrypt), any())).thenThrow(exception);

    Aead aead = new HcVaultKmsAead(mockKms, uri);
    byte[] ciphertext = Random.randBytes(20);
    byte[] aad = Random.randBytes(20);
    try {
      aead.decrypt(ciphertext, aad);
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      // expected.
    }
  }
}
