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

package com.google.crypto.tink.tinkey;

import static com.google.common.truth.Truth.assertThat;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertTrue;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.TinkJsonProtoKeysetFormat;
import com.google.crypto.tink.TinkProtoKeysetFormat;
import com.google.crypto.tink.aead.AeadConfig;
import com.google.crypto.tink.aead.PredefinedAeadParameters;
import com.google.crypto.tink.mac.MacConfig;
import com.google.crypto.tink.mac.PredefinedMacParameters;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class ConvertKeysetCommandTest {
  private Path tempDirectory;
  private Path credentialFile;
  private KeysetHandle masterKeyAeadKeyset;
  private Aead masterKeyAead;
  private String masterKeyUri;

  @BeforeClass
  public static void setUp() throws Exception {
    AeadConfig.register();
    MacConfig.register();
    KmsClientsFactory.globalInstance().addFactory(TinkeyTestKmsClient::new);
  }

  @Before
  public void setUpEncryption() throws Exception {
    tempDirectory = Files.createTempDirectory(/* prefix= */ "");
    credentialFile = Paths.get(tempDirectory.toString(), "credentials");
    TinkeyTestKmsClient.createCredentialFile(credentialFile);

    masterKeyAeadKeyset = KeysetHandle.generateNew(PredefinedAeadParameters.AES128_GCM);
    masterKeyAead = masterKeyAeadKeyset.getPrimitive(Aead.class);
    masterKeyUri = TinkeyTestKmsClient.createKeyUri(masterKeyAeadKeyset);
  }

  private static KeysetHandle createArbitraryKeyset() throws GeneralSecurityException {
    return KeysetHandle.newBuilder()
        .addEntry(
            KeysetHandle.generateEntryFromParameters(PredefinedMacParameters.HMAC_SHA256_128BITTAG)
                .withRandomId()
                .makePrimary())
        .addEntry(
            KeysetHandle.generateEntryFromParameters(PredefinedMacParameters.HMAC_SHA256_128BITTAG)
                .withRandomId())
        .build();
  }

  @Test
  public void testConvertKeyset_json2Binary_works() throws Exception {
    Path inputFile = Paths.get(tempDirectory.toString(), "input");
    Path outputFile = Paths.get(tempDirectory.toString(), "output");

    KeysetHandle inputKeyset = createArbitraryKeyset();
    String serializedKeyset =
        TinkJsonProtoKeysetFormat.serializeKeyset(inputKeyset, InsecureSecretKeyAccess.get());
    Files.write(inputFile, serializedKeyset.getBytes(UTF_8));

    Tinkey.main(
        new String[] {
          "convert-keyset",
          "--in",
          inputFile.toString(),
          "--out",
          outputFile.toString(),
          "--in-format",
          "json",
          "--out-format",
          "binary",
        });

    KeysetHandle outputKeyset =
        TinkProtoKeysetFormat.parseKeyset(
            Files.readAllBytes(outputFile), InsecureSecretKeyAccess.get());

    assertThat(outputKeyset.size()).isEqualTo(inputKeyset.size());
    for (int i = 0; i < inputKeyset.size(); i++) {
      assertTrue(outputKeyset.getAt(i).getKey().equalsKey(inputKeyset.getAt(i).getKey()));
    }
  }

  @Test
  public void testConvertKeyset_binary2Json_works() throws Exception {
    Path inputFile = Paths.get(tempDirectory.toString(), "input");
    Path outputFile = Paths.get(tempDirectory.toString(), "output");

    KeysetHandle inputKeyset = createArbitraryKeyset();
    byte[] serializedKeyset =
        TinkProtoKeysetFormat.serializeKeyset(inputKeyset, InsecureSecretKeyAccess.get());
    Files.write(inputFile, serializedKeyset);

    Tinkey.main(
        new String[] {
          "convert-keyset",
          "--in",
          inputFile.toString(),
          "--out",
          outputFile.toString(),
          "--in-format",
          "binary",
          "--out-format",
          "json",
        });

    KeysetHandle outputKeyset =
        TinkJsonProtoKeysetFormat.parseKeyset(
            new String(Files.readAllBytes(outputFile), UTF_8), InsecureSecretKeyAccess.get());

    assertThat(outputKeyset.size()).isEqualTo(inputKeyset.size());
    for (int i = 0; i < inputKeyset.size(); i++) {
      assertTrue(outputKeyset.getAt(i).getKey().equalsKey(inputKeyset.getAt(i).getKey()));
    }
  }

  @Test
  public void testConvertKeyset_json2encryptedBinary_works() throws Exception {
    Path inputFile = Paths.get(tempDirectory.toString(), "input");
    Path outputFile = Paths.get(tempDirectory.toString(), "output");

    KeysetHandle inputKeyset = createArbitraryKeyset();
    byte[] serializedKeyset =
        TinkProtoKeysetFormat.serializeKeyset(inputKeyset, InsecureSecretKeyAccess.get());
    Files.write(inputFile, serializedKeyset);
    Tinkey.main(
        new String[] {
          "convert-keyset",
          "--in",
          inputFile.toString(),
          "--out",
          outputFile.toString(),
          "--in-format",
          "binary",
          "--out-format",
          "json",
          "--new-master-key-uri",
          masterKeyUri,
          "--new-credential",
          credentialFile.toString(),
        });

    KeysetHandle outputKeyset =
        TinkJsonProtoKeysetFormat.parseEncryptedKeyset(
            new String(Files.readAllBytes(outputFile), UTF_8), masterKeyAead, new byte[] {});

    assertThat(outputKeyset.size()).isEqualTo(inputKeyset.size());
    for (int i = 0; i < inputKeyset.size(); i++) {
      assertTrue(outputKeyset.getAt(i).getKey().equalsKey(inputKeyset.getAt(i).getKey()));
    }
  }

  @Test
  public void testConvertKeyset_encryptedBinary2Json_works() throws Exception {
    Path inputFile = Paths.get(tempDirectory.toString(), "input");
    Path outputFile = Paths.get(tempDirectory.toString(), "output");

    KeysetHandle inputKeyset = createArbitraryKeyset();
    byte[] serializedKeyset =
        TinkProtoKeysetFormat.serializeEncryptedKeyset(inputKeyset, masterKeyAead, new byte[] {});
    Files.write(inputFile, serializedKeyset);
    Tinkey.main(
        new String[] {
          "convert-keyset",
          "--in",
          inputFile.toString(),
          "--out",
          outputFile.toString(),
          "--in-format",
          "binary",
          "--out-format",
          "json",
          "--master-key-uri",
          masterKeyUri,
          "--credential",
          credentialFile.toString(),
        });

    KeysetHandle outputKeyset =
        TinkJsonProtoKeysetFormat.parseKeyset(
            new String(Files.readAllBytes(outputFile), UTF_8), InsecureSecretKeyAccess.get());

    assertThat(outputKeyset.size()).isEqualTo(inputKeyset.size());
    for (int i = 0; i < inputKeyset.size(); i++) {
      assertTrue(outputKeyset.getAt(i).getKey().equalsKey(inputKeyset.getAt(i).getKey()));
    }
  }
}
