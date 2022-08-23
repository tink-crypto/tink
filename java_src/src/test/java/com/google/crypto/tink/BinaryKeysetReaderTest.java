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

package com.google.crypto.tink;

import static com.google.common.truth.Truth.assertThat;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.aead.AeadConfig;
import com.google.crypto.tink.mac.MacConfig;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.GeneralSecurityException;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for BinaryKeysetReader. */
@RunWith(JUnit4.class)
public class BinaryKeysetReaderTest {

  @BeforeClass
  public static void setUp() throws GeneralSecurityException {
    MacConfig.register();
    AeadConfig.register();
  }

  private void assertKeysetHandle(KeysetHandle handle1, KeysetHandle handle2) throws Exception {
    Mac mac1 = handle1.getPrimitive(Mac.class);
    Mac mac2 = handle2.getPrimitive(Mac.class);
    byte[] message = "message".getBytes(UTF_8);

    assertThat(handle2.getKeyset()).isEqualTo(handle1.getKeyset());
    mac2.verifyMac(mac1.computeMac(message), message);
  }

  @Test
  public void testReadWithInputStream_singleKey_shouldWork() throws Exception {
    KeyTemplate template = KeyTemplates.get("HMAC_SHA256_128BITTAG");
    KeysetHandle handle1 = KeysetHandle.generateNew(template);
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    CleartextKeysetHandle.write(handle1, BinaryKeysetWriter.withOutputStream(outputStream));
    KeysetHandle handle2 =
        CleartextKeysetHandle.read(
            BinaryKeysetReader.withInputStream(
                new ByteArrayInputStream(outputStream.toByteArray())));

    assertKeysetHandle(handle1, handle2);
  }

  @Test
  public void testReadWithInputStream_multipleKeys_shouldWork() throws Exception {
    KeysetHandle handle1 =
        KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.generateEntryFromParametersName("HMAC_SHA256_128BITTAG")
                    .withRandomId()
                    .makePrimary())
            .addEntry(
                KeysetHandle.generateEntryFromParametersName("HMAC_SHA256_128BITTAG")
                    .withRandomId())
            .addEntry(
                KeysetHandle.generateEntryFromParametersName("HMAC_SHA256_128BITTAG")
                    .withRandomId())
            .build();

    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    CleartextKeysetHandle.write(handle1, BinaryKeysetWriter.withOutputStream(outputStream));
    KeysetHandle handle2 =
        CleartextKeysetHandle.read(
            BinaryKeysetReader.withInputStream(
                new ByteArrayInputStream(outputStream.toByteArray())));

    assertKeysetHandle(handle1, handle2);
  }

  @Test
  public void testReadWithBytes_shouldWork() throws Exception {
    KeyTemplate template = KeyTemplates.get("HMAC_SHA256_128BITTAG");
    KeysetHandle handle1 = KeysetHandle.generateNew(template);
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    CleartextKeysetHandle.write(handle1, BinaryKeysetWriter.withOutputStream(outputStream));
    byte[] binaryKeyset = outputStream.toByteArray();

    KeysetReader reader = BinaryKeysetReader.withBytes(binaryKeyset);
    KeysetHandle handle2 = CleartextKeysetHandle.read(reader);
    assertKeysetHandle(handle1, handle2);
  }

  @Test
  public void testWithBytesReadTwice_fails() throws Exception {
    KeyTemplate template = KeyTemplates.get("HMAC_SHA256_128BITTAG");
    KeysetHandle handle1 = KeysetHandle.generateNew(template);
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    CleartextKeysetHandle.write(handle1, BinaryKeysetWriter.withOutputStream(outputStream));
    byte[] binaryKeyset = outputStream.toByteArray();

    KeysetReader reader = BinaryKeysetReader.withBytes(binaryKeyset);
    KeysetHandle unused = CleartextKeysetHandle.read(reader);

    assertThrows(
        GeneralSecurityException.class,
        () -> CleartextKeysetHandle.read(reader));
  }

  @Test
  public void testReadEncrypted_singleKey_shouldWork() throws Exception {
    Aead keysetEncryptionAead =
        KeysetHandle.generateNew(KeyTemplates.get("AES128_EAX")).getPrimitive(Aead.class);
    KeysetHandle handle1 = KeysetHandle.generateNew(KeyTemplates.get("HMAC_SHA256_128BITTAG"));
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    handle1.write(BinaryKeysetWriter.withOutputStream(outputStream), keysetEncryptionAead);
    KeysetHandle handle2 =
        KeysetHandle.read(
            BinaryKeysetReader.withInputStream(
                new ByteArrayInputStream(outputStream.toByteArray())),
            keysetEncryptionAead);

    assertKeysetHandle(handle1, handle2);
  }

  @Test
  public void testReadEncrypted_multipleKeys_shouldWork() throws Exception {
    KeysetHandle handle1 =
        KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.generateEntryFromParametersName("HMAC_SHA256_128BITTAG")
                    .withRandomId()
                    .makePrimary())
            .addEntry(
                KeysetHandle.generateEntryFromParametersName("HMAC_SHA256_128BITTAG_RAW")
                    .withRandomId())
            .addEntry(
                KeysetHandle.generateEntryFromParametersName("HMAC_SHA256_256BITTAG")
                    .withRandomId().setStatus(KeyStatus.DESTROYED))
            .addEntry(
                KeysetHandle.generateEntryFromParametersName("HMAC_SHA256_256BITTAG_RAW")
                    .withRandomId().setStatus(KeyStatus.DISABLED))
            .addEntry(
                KeysetHandle.generateEntryFromParametersName("AES256_CMAC")
                    .withRandomId())
            .build();

    Aead keysetEncryptionAead =
        KeysetHandle.generateNew(KeyTemplates.get("AES128_EAX")).getPrimitive(Aead.class);
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    handle1.write(BinaryKeysetWriter.withOutputStream(outputStream), keysetEncryptionAead);
    KeysetHandle handle2 =
        KeysetHandle.read(
            BinaryKeysetReader.withInputStream(
                new ByteArrayInputStream(outputStream.toByteArray())),
            keysetEncryptionAead);

    assertKeysetHandle(handle1, handle2);
  }

}
