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

package com.google.crypto.tink.tinkey;

import static com.google.common.truth.Truth.assertThat;

import com.google.crypto.tink.CleartextKeysetHandle;
import com.google.crypto.tink.Config;
import com.google.crypto.tink.HybridDecrypt;
import com.google.crypto.tink.HybridEncrypt;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.KeysetReader;
import com.google.crypto.tink.PublicKeySign;
import com.google.crypto.tink.PublicKeyVerify;
import com.google.crypto.tink.TestUtil;
import com.google.crypto.tink.config.TinkConfig;
import com.google.crypto.tink.hybrid.HybridDecryptFactory;
import com.google.crypto.tink.hybrid.HybridEncryptFactory;
import com.google.crypto.tink.hybrid.HybridKeyTemplates;
import com.google.crypto.tink.proto.EncryptedKeyset;
import com.google.crypto.tink.proto.KeyTemplate;
import com.google.crypto.tink.proto.Keyset;
import com.google.crypto.tink.signature.PublicKeySignFactory;
import com.google.crypto.tink.signature.PublicKeyVerifyFactory;
import com.google.crypto.tink.signature.SignatureKeyTemplates;
import com.google.crypto.tink.subtle.Random;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Tests for {@code CreatePublicKeysetCommand}.
 */
@RunWith(JUnit4.class)
public class CreatePublicKeysetCommandTest {
  private enum KeyType {
    HYBRID,
    SIGNATURE,
  };

  private static final String OUTPUT_FORMAT = "json";
  private static final String INPUT_FORMAT = "json";

  @BeforeClass
  public static void setUp() throws Exception {
    Config.register(TinkConfig.TINK_1_0_0);
  }

  @Test
  public void testCreate_hybrid_cleartextPrivate_shouldCreateCleartextPublic()
      throws Exception {
    testCreate_cleartextPrivate_shouldCreateCleartextPublic(
        HybridKeyTemplates.ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM, KeyType.HYBRID);
  }

  @Test
  public void testCreate_hybrid_encryptedPrivate_shouldCreateCleartextPublic()
      throws Exception {
    testCreate_encryptedPrivate_shouldCreateCleartextPublic(
        HybridKeyTemplates.ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM, KeyType.HYBRID);
  }

  @Test
  public void testCreate_signature_cleartextPrivate_shouldCreateCleartextPublic()
      throws Exception {
    testCreate_cleartextPrivate_shouldCreateCleartextPublic(
        SignatureKeyTemplates.ECDSA_P256, KeyType.SIGNATURE);
    testCreate_cleartextPrivate_shouldCreateCleartextPublic(
        SignatureKeyTemplates.ED25519, KeyType.SIGNATURE);
  }

  @Test
  public void testCreate_signature_encryptedPrivate_shouldCreateCleartextPublic()
      throws Exception {
    testCreate_encryptedPrivate_shouldCreateCleartextPublic(
        SignatureKeyTemplates.ECDSA_P256, KeyType.SIGNATURE);
    testCreate_encryptedPrivate_shouldCreateCleartextPublic(
        SignatureKeyTemplates.ED25519, KeyType.SIGNATURE);
  }

  private void testCreate_cleartextPrivate_shouldCreateCleartextPublic(
      KeyTemplate template, KeyType type) throws Exception {
    // Create a cleartext private keyset.
    String masterKeyUri = null;
    String credentialPath = null;
    InputStream inputStream1 = TinkeyUtil.createKeyset(
        template, INPUT_FORMAT, masterKeyUri, credentialPath);
    KeysetReader privateReader = TinkeyUtil
        .createKeysetReader(inputStream1, INPUT_FORMAT);
    // Create the public keyset.
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    inputStream1.mark(inputStream1.available());
    CreatePublicKeysetCommand.create(
        outputStream, OUTPUT_FORMAT,
        inputStream1, INPUT_FORMAT,
        masterKeyUri, credentialPath);
    inputStream1.reset();
    InputStream inputStream2 = new ByteArrayInputStream(outputStream.toByteArray());
    KeysetReader publicReader = TinkeyUtil
        .createKeysetReader(inputStream2, OUTPUT_FORMAT);

    assertPublicKey(type, privateReader, publicReader);
  }

  private void testCreate_encryptedPrivate_shouldCreateCleartextPublic(
      KeyTemplate template, KeyType type) throws Exception {
    // Create an input stream containing a cleartext private keyset.
    String masterKeyUri = TestUtil.RESTRICTED_CRYPTO_KEY_URI;
    String credentialPath = TestUtil.SERVICE_ACCOUNT_FILE;
    InputStream inputStream1 = TinkeyUtil.createKeyset(
        template, INPUT_FORMAT, masterKeyUri, credentialPath);
    inputStream1.mark(inputStream1.available());
    final KeysetHandle privateHandle = TinkeyUtil.getKeysetHandle(
        inputStream1, INPUT_FORMAT, masterKeyUri, credentialPath);
    inputStream1.reset();
    KeysetReader privateReader = new KeysetReader() {
        @Override
        public Keyset read() throws IOException {
            return TestUtil.getKeyset(privateHandle);
        }
        @Override
        public EncryptedKeyset readEncrypted() throws IOException {
            throw new IOException("Not Implemented");
        }
    };
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    inputStream1.mark(inputStream1.available());
    CreatePublicKeysetCommand.create(
        outputStream, OUTPUT_FORMAT,
        inputStream1, INPUT_FORMAT,
        masterKeyUri, credentialPath);
    inputStream1.reset();
    InputStream inputStream2 = new ByteArrayInputStream(outputStream.toByteArray());
    KeysetReader publicReader = TinkeyUtil
        .createKeysetReader(inputStream2, OUTPUT_FORMAT);

    assertPublicKey(type, privateReader, publicReader);
  }

  private void assertHybrid(KeysetReader privateReader, KeysetReader publicReader)
    throws Exception {
    HybridDecrypt decrypter = HybridDecryptFactory.getPrimitive(
        CleartextKeysetHandle.read(privateReader));
    HybridEncrypt encrypter = HybridEncryptFactory.getPrimitive(
        CleartextKeysetHandle.read(publicReader));
    byte[] message = Random.randBytes(10);
    byte[] contextInfo = Random.randBytes(20);

    assertThat(decrypter.decrypt(encrypter.encrypt(message, contextInfo), contextInfo)).isEqualTo(
        message);
  }

  private void assertSignature(KeysetReader privateReader, KeysetReader publicReader)
    throws Exception {
    byte[] message = Random.randBytes(10);
    PublicKeySign signer = PublicKeySignFactory.getPrimitive(
        CleartextKeysetHandle.read(privateReader));
    PublicKeyVerify verifier = PublicKeyVerifyFactory.getPrimitive(
        CleartextKeysetHandle.read(publicReader));

    verifier.verify(signer.sign(message), message);
  }

  private void assertPublicKey(KeyType type, KeysetReader privateReader,
      KeysetReader publicReader) throws Exception {
    switch (type) {
        case HYBRID:
            assertHybrid(privateReader, publicReader);
            break;
        case SIGNATURE:
            assertSignature(privateReader, publicReader);
            break;
        default:
            throw new Exception("not supported: " + type);
    }
  }
}
