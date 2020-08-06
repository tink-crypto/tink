package com.google.crypto.tink.integration.hcvault;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.KmsClient;

import com.bettercloud.vault.Vault;
import com.bettercloud.vault.VaultConfig;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.isA;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertThrows;
import static org.mockito.Mockito.when;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;

@RunWith(MockitoJUnitRunner.class)
public class HcVaultKmsClientTest {
  public static final String defaultCreds = "hcvault://hcvault.corp.com:8200/transit/keys/key-1";
  public static final String uri = "hcvault://transit/keys/key-1";

  public static final String invalidUri = "hcvault://transit/keys/key-2";

  @Test
  public void testWithCredentials() throws Exception {
    KmsClient client = new HcVaultKmsClient(uri).withCredentials(defaultCreds);
    HcVaultKmsClient hcvClient = (HcVaultKmsClient) client;
    assertThat(hcvClient.doesSupport(invalidUri), equalTo(false));
    assertThat(hcvClient.doesSupport(uri), equalTo(true));
  }

  @Test
  public void testWithUri() throws Exception {
    HcVaultKmsClient client = new HcVaultKmsClient(uri);
    assertThat(client.doesSupport(invalidUri), equalTo(false));
    assertThat(client.doesSupport(uri), equalTo(true));
  }

  @Test
  public void testGetAead() throws Exception {
    KmsClient client = new HcVaultKmsClient(uri);

    assertThrows(GeneralSecurityException.class, () -> client.getAead(null));
    assertThrows(GeneralSecurityException.class, () -> client.getAead(""));
    assertThrows(GeneralSecurityException.class, () -> client.getAead(invalidUri));

    Aead aead = client.getAead(uri);
    assertThat(aead, isA(Aead.class));
  }
}
