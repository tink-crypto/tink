// Copyright 2022 Google LLC
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

package com.google.crypto.tink.hybrid;

import static com.google.common.truth.Truth.assertThat;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.HybridDecrypt;
import com.google.crypto.tink.HybridEncrypt;
import com.google.crypto.tink.PrimitiveSet;
import com.google.crypto.tink.Registry;
import com.google.crypto.tink.aead.AeadKeyTemplates;
import com.google.crypto.tink.internal.MutableMonitoringRegistry;
import com.google.crypto.tink.internal.testing.FakeMonitoringClient;
import com.google.crypto.tink.monitoring.MonitoringAnnotations;
import com.google.crypto.tink.proto.EcPointFormat;
import com.google.crypto.tink.proto.EciesAeadHkdfPrivateKey;
import com.google.crypto.tink.proto.EciesAeadHkdfPublicKey;
import com.google.crypto.tink.proto.EllipticCurveType;
import com.google.crypto.tink.proto.HashType;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.proto.KeyStatusType;
import com.google.crypto.tink.proto.Keyset.Key;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.crypto.tink.subtle.Bytes;
import com.google.crypto.tink.testing.TestUtil;
import java.security.GeneralSecurityException;
import java.util.List;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

/** Tests for {@link HybridDecryptWrapper}. */
@RunWith(Theories.class)
public class HybridDecryptWrapperTest {

  private static EciesAeadHkdfPrivateKey eciesAeadHkdfPrivateKey1;
  private static EciesAeadHkdfPrivateKey eciesAeadHkdfPrivateKey2;

  @BeforeClass
  @SuppressWarnings("deprecation") // TestUtil.generateEciesAeadHkdfPrivKey uses proto templates.
  public static void setUp() throws Exception {
    HybridConfig.register();

    eciesAeadHkdfPrivateKey1 =
        TestUtil.generateEciesAeadHkdfPrivKey(
            EllipticCurveType.NIST_P384,
            HashType.SHA256,
            EcPointFormat.UNCOMPRESSED,
            AeadKeyTemplates.AES128_CTR_HMAC_SHA256,
            "some salt".getBytes(UTF_8));
    eciesAeadHkdfPrivateKey2 =
        TestUtil.generateEciesAeadHkdfPrivKey(
            EllipticCurveType.NIST_P384,
            HashType.SHA256,
            EcPointFormat.COMPRESSED,
            AeadKeyTemplates.AES128_CTR_HMAC_SHA256,
            "other salt".getBytes(UTF_8));
  }

  private static Key getPublicKey(
      EciesAeadHkdfPublicKey eciesAeadHkdfPublicKey, int keyId, OutputPrefixType prefixType)
      throws Exception {
    return TestUtil.createKey(
        TestUtil.createKeyData(
            eciesAeadHkdfPublicKey,
            "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPublicKey",
            KeyData.KeyMaterialType.ASYMMETRIC_PUBLIC),
        keyId,
        KeyStatusType.ENABLED,
        prefixType);
  }

  private static Key getPrivateKey(
      EciesAeadHkdfPrivateKey eciesAeadHkdfPrivateKey, int keyId, OutputPrefixType prefixType)
      throws Exception {
    return TestUtil.createKey(
        TestUtil.createKeyData(
            eciesAeadHkdfPrivateKey,
            "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPrivateKey",
            KeyData.KeyMaterialType.ASYMMETRIC_PRIVATE),
        keyId,
        KeyStatusType.ENABLED,
        prefixType);
  }

  @Test
  public void decryptRaw_worksWithCiphertextFromRawEncrypter() throws Exception {
    Key privateKey =
        getPrivateKey(eciesAeadHkdfPrivateKey1, /*keyId=*/ 0x66AABBCC, OutputPrefixType.RAW);
    Key publicKey =
        getPublicKey(
            eciesAeadHkdfPrivateKey1.getPublicKey(), /*keyId=*/ 0x66AABBCC, OutputPrefixType.RAW);

    HybridEncrypt rawEncrypter = Registry.getPrimitive(publicKey.getKeyData(), HybridEncrypt.class);

    PrimitiveSet<HybridDecrypt> primitives =
        PrimitiveSet.newBuilder(HybridDecrypt.class)
            .addPrimaryPrimitive(
                Registry.getPrimitive(privateKey.getKeyData(), HybridDecrypt.class), privateKey)
            .build();
    HybridDecrypt wrappedDecrypter = new HybridDecryptWrapper().wrap(primitives);

    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] contextInfo = "contextInfo".getBytes(UTF_8);

    byte[] ciphertext = rawEncrypter.encrypt(plaintext, contextInfo);
    assertThat(wrappedDecrypter.decrypt(ciphertext, contextInfo)).isEqualTo(plaintext);

    byte[] ciphertextWithTinkPrefix = Bytes.concat(TestUtil.hexDecode("0166AABBCC"), ciphertext);
    byte[] ciphertextWithLegacyPrefix = Bytes.concat(TestUtil.hexDecode("0066AABBCC"), ciphertext);
    assertThrows(
        GeneralSecurityException.class,
        () -> wrappedDecrypter.decrypt(ciphertextWithTinkPrefix, contextInfo));
    assertThrows(
        GeneralSecurityException.class,
        () -> wrappedDecrypter.decrypt(ciphertextWithLegacyPrefix, contextInfo));
    assertThrows(
        GeneralSecurityException.class,
        () -> wrappedDecrypter.decrypt(ciphertext, "invalid".getBytes(UTF_8)));
    assertThrows(
        GeneralSecurityException.class,
        () -> wrappedDecrypter.decrypt("invalid".getBytes(UTF_8), contextInfo));
    assertThrows(
        GeneralSecurityException.class,
        () -> wrappedDecrypter.decrypt("".getBytes(UTF_8), contextInfo));
  }

  @Test
  public void decryptTink_worksWithRawCiphertextWithTinkPrefix() throws Exception {
    Key privateKey =
        getPrivateKey(eciesAeadHkdfPrivateKey1, /*keyId=*/ 0x66AABBCC, OutputPrefixType.TINK);
    Key publicKey =
        getPublicKey(
            eciesAeadHkdfPrivateKey1.getPublicKey(), /*keyId=*/ 0x66AABBCC, OutputPrefixType.TINK);

    HybridEncrypt rawEncrypter = Registry.getPrimitive(publicKey.getKeyData(), HybridEncrypt.class);

    PrimitiveSet<HybridDecrypt> primitives =
        PrimitiveSet.newBuilder(HybridDecrypt.class)
            .addPrimaryPrimitive(
                Registry.getPrimitive(privateKey.getKeyData(), HybridDecrypt.class), privateKey)
            .build();
    HybridDecrypt wrappedDecrypter = new HybridDecryptWrapper().wrap(primitives);

    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] contextInfo = "contextInfo".getBytes(UTF_8);

    byte[] rawCiphertext = rawEncrypter.encrypt(plaintext, contextInfo);

    byte[] ciphertextWithTinkPrefix = Bytes.concat(TestUtil.hexDecode("0166AABBCC"), rawCiphertext);

    assertThat(wrappedDecrypter.decrypt(ciphertextWithTinkPrefix, contextInfo))
        .isEqualTo(plaintext);

    assertThrows(
        GeneralSecurityException.class,
        () -> wrappedDecrypter.decrypt(rawCiphertext, contextInfo));
    byte[] ciphertextWithLegacyPrefix =
        Bytes.concat(TestUtil.hexDecode("0066AABBCC"), rawCiphertext);
    assertThrows(
        GeneralSecurityException.class,
        () -> wrappedDecrypter.decrypt(ciphertextWithLegacyPrefix, contextInfo));
    assertThrows(
        GeneralSecurityException.class,
        () -> wrappedDecrypter.decrypt(ciphertextWithTinkPrefix, "invalid".getBytes(UTF_8)));
    assertThrows(
        GeneralSecurityException.class,
        () -> wrappedDecrypter.decrypt("invalid".getBytes(UTF_8), contextInfo));
    assertThrows(
        GeneralSecurityException.class,
        () -> wrappedDecrypter.decrypt("".getBytes(UTF_8), contextInfo));
  }

  @DataPoints("outputPrefixType")
  public static final OutputPrefixType[] OUTPUT_PREFIX_TYPES =
      new OutputPrefixType[] {
        OutputPrefixType.LEGACY,
        OutputPrefixType.CRUNCHY,
        OutputPrefixType.TINK,
        OutputPrefixType.RAW
      };

  @Theory
  public void decrypt_canDecryptCiphertextEncryptedByHybridEncryptWrapper(
      @FromDataPoints("outputPrefixType") OutputPrefixType prefix) throws Exception {
    PrimitiveSet<HybridEncrypt> encryptPrimitives =
        TestUtil.createPrimitiveSet(
            TestUtil.createKeyset(
                getPublicKey(eciesAeadHkdfPrivateKey1.getPublicKey(), /*keyId=*/ 123, prefix)),
            HybridEncrypt.class);
    HybridEncrypt encrypter = new HybridEncryptWrapper().wrap(encryptPrimitives);

    PrimitiveSet<HybridDecrypt> decryptPrimitives =
        TestUtil.createPrimitiveSet(
            TestUtil.createKeyset(
                getPrivateKey(eciesAeadHkdfPrivateKey1, /*keyId=*/ 123, prefix)),
            HybridDecrypt.class);
    HybridDecrypt decrypter = new HybridDecryptWrapper().wrap(decryptPrimitives);

    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] contextInfo = "contextInfo".getBytes(UTF_8);

    byte[] ciphertext = encrypter.encrypt(plaintext, contextInfo);

    assertThat(decrypter.decrypt(ciphertext, contextInfo)).isEqualTo(plaintext);
  }

  @Theory
  public void failsIfEncryptedByOtherKeyEvenIfKeyIdsAreEqual(
      @FromDataPoints("outputPrefixType") OutputPrefixType prefix) throws Exception {
    PrimitiveSet<HybridEncrypt> encPrimitives2 =
        TestUtil.createPrimitiveSet(
            TestUtil.createKeyset(
                getPublicKey(eciesAeadHkdfPrivateKey2.getPublicKey(), /*keyId=*/ 123, prefix)),
            HybridEncrypt.class);
    HybridEncrypt encrypter2 = new HybridEncryptWrapper().wrap(encPrimitives2);

    PrimitiveSet<HybridDecrypt> decPrimitives1 =
        TestUtil.createPrimitiveSet(
            TestUtil.createKeyset(getPrivateKey(eciesAeadHkdfPrivateKey1, /*keyId=*/ 123, prefix)),
            HybridDecrypt.class);
    HybridDecrypt decrypter1 = new HybridDecryptWrapper().wrap(decPrimitives1);

    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] contextInfo = "contextInfo".getBytes(UTF_8);

    byte[] ciphertext = encrypter2.encrypt(plaintext, contextInfo);
    assertThrows(GeneralSecurityException.class, () -> decrypter1.decrypt(ciphertext, contextInfo));
  }

  @Theory
  public void decryptWorksIfCiphertextIsValidForAnyPrimitiveInThePrimitiveSet(
      @FromDataPoints("outputPrefixType") OutputPrefixType prefix1,
      @FromDataPoints("outputPrefixType") OutputPrefixType prefix2)
      throws Exception {
    HybridEncrypt encrypter1 =
        new HybridEncryptWrapper()
            .wrap(
                TestUtil.createPrimitiveSet(
                    TestUtil.createKeyset(
                        getPublicKey(
                            eciesAeadHkdfPrivateKey1.getPublicKey(), /*keyId=*/ 123, prefix1)),
                    HybridEncrypt.class));
    HybridEncrypt encrypter2 =
        new HybridEncryptWrapper()
            .wrap(
                TestUtil.createPrimitiveSet(
                    TestUtil.createKeyset(
                        getPublicKey(
                            eciesAeadHkdfPrivateKey2.getPublicKey(), /*keyId=*/ 234, prefix2)),
                    HybridEncrypt.class));

    PrimitiveSet<HybridDecrypt> decryptPrimitives =
        TestUtil.createPrimitiveSet(
            TestUtil.createKeyset(
                getPrivateKey(eciesAeadHkdfPrivateKey1, /*keyId=*/ 123, prefix1),
                getPrivateKey(eciesAeadHkdfPrivateKey2, /*keyId=*/ 234, prefix2)),
            HybridDecrypt.class);
    HybridDecrypt decrypter = new HybridDecryptWrapper().wrap(decryptPrimitives);

    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] contextInfo = "contextInfo".getBytes(UTF_8);

    byte[] ciphertext1 = encrypter1.encrypt(plaintext, contextInfo);
    byte[] ciphertext2 = encrypter2.encrypt(plaintext, contextInfo);
    assertThat(decrypter.decrypt(ciphertext1, contextInfo)).isEqualTo(plaintext);
    assertThat(decrypter.decrypt(ciphertext2, contextInfo)).isEqualTo(plaintext);
  }

  @Theory
  public void decryptWithoutPrimary_works() throws Exception {
    HybridEncrypt encrypter =
        new HybridEncryptWrapper()
            .wrap(
                TestUtil.createPrimitiveSet(
                    TestUtil.createKeyset(
                        getPublicKey(
                            eciesAeadHkdfPrivateKey1.getPublicKey(),
                            /*keyId=*/ 123,
                            OutputPrefixType.TINK)),
                    HybridEncrypt.class));
    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] contextInfo = "contextInfo".getBytes(UTF_8);
    byte[] ciphertext = encrypter.encrypt(plaintext, contextInfo);

    Key privateKey = getPrivateKey(eciesAeadHkdfPrivateKey1, /*keyId=*/ 123, OutputPrefixType.TINK);
    HybridDecrypt rawDecrypter =
        Registry.getPrimitive(privateKey.getKeyData(), HybridDecrypt.class);
    PrimitiveSet<HybridDecrypt> primitivesWithoutPrimary =
        PrimitiveSet.newBuilder(HybridDecrypt.class)
            .addPrimitive(rawDecrypter, privateKey)
            .build();
    HybridDecrypt decrypterWithoutPrimary =
        new HybridDecryptWrapper().wrap(primitivesWithoutPrimary);

    assertThat(decrypterWithoutPrimary.decrypt(ciphertext, contextInfo)).isEqualTo(plaintext);
  }

  @DataPoints("nonRawOutputPrefixType")
  public static final OutputPrefixType[] NON_RAW_OUTPUT_PREFIX_TYPES =
      new OutputPrefixType[] {
        OutputPrefixType.LEGACY, OutputPrefixType.CRUNCHY, OutputPrefixType.TINK
      };

  @Theory
  public void nonRawKeyPairWithTwoDifferentKeyIds_decryptFails(
      @FromDataPoints("nonRawOutputPrefixType") OutputPrefixType prefix) throws Exception {
    PrimitiveSet<HybridEncrypt> encryptPrimitives =
        TestUtil.createPrimitiveSet(
            TestUtil.createKeyset(
                getPublicKey(eciesAeadHkdfPrivateKey1.getPublicKey(), /*keyId=*/ 123, prefix)),
            HybridEncrypt.class);
    HybridEncrypt encrypter = new HybridEncryptWrapper().wrap(encryptPrimitives);

    PrimitiveSet<HybridDecrypt> decryptPrimitives =
        TestUtil.createPrimitiveSet(
            TestUtil.createKeyset(
                getPrivateKey(eciesAeadHkdfPrivateKey1, /*keyId=*/ 234, prefix)),
            HybridDecrypt.class);
    HybridDecrypt decrypter = new HybridDecryptWrapper().wrap(decryptPrimitives);

    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] contextInfo = "contextInfo".getBytes(UTF_8);

    byte[] ciphertext = encrypter.encrypt(plaintext, contextInfo);

    assertThrows(GeneralSecurityException.class, () -> decrypter.decrypt(ciphertext, contextInfo));
  }

  @Theory
  public void rawKeyPairWithTwoDifferentKeyIds_decryptWorks() throws Exception {
    PrimitiveSet<HybridEncrypt> encryptPrimitives =
        TestUtil.createPrimitiveSet(
            TestUtil.createKeyset(
                getPublicKey(
                    eciesAeadHkdfPrivateKey1.getPublicKey(), /*keyId=*/ 123, OutputPrefixType.RAW)),
            HybridEncrypt.class);
    HybridEncrypt encrypter = new HybridEncryptWrapper().wrap(encryptPrimitives);

    PrimitiveSet<HybridDecrypt> decryptPrimitives =
        TestUtil.createPrimitiveSet(
            TestUtil.createKeyset(
                getPrivateKey(eciesAeadHkdfPrivateKey1, /*keyId=*/ 234, OutputPrefixType.RAW)),
            HybridDecrypt.class);
    HybridDecrypt decrypter = new HybridDecryptWrapper().wrap(decryptPrimitives);

    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] contextInfo = "contextInfo".getBytes(UTF_8);

    byte[] ciphertext = encrypter.encrypt(plaintext, contextInfo);

    assertThat(decrypter.decrypt(ciphertext, contextInfo)).isEqualTo(plaintext);
  }

  @Theory
  public void doesNotMonitorWithoutAnnotations() throws Exception {
    FakeMonitoringClient fakeMonitoringClient = new FakeMonitoringClient();
    MutableMonitoringRegistry.globalInstance().clear();
    MutableMonitoringRegistry.globalInstance().registerMonitoringClient(fakeMonitoringClient);

    PrimitiveSet<HybridEncrypt> encPrimitives =
        TestUtil.createPrimitiveSet(
            TestUtil.createKeyset(
                getPublicKey(
                    eciesAeadHkdfPrivateKey1.getPublicKey(),
                    /*keyId=*/ 123,
                    OutputPrefixType.TINK)),
            HybridEncrypt.class);
    HybridEncrypt encrypter = new HybridEncryptWrapper().wrap(encPrimitives);

    PrimitiveSet<HybridDecrypt> decPrimitives =
        TestUtil.createPrimitiveSet(
            TestUtil.createKeyset(
                getPrivateKey(eciesAeadHkdfPrivateKey1, /*keyId=*/ 123, OutputPrefixType.TINK)),
            HybridDecrypt.class);
    HybridDecrypt decrypter = new HybridDecryptWrapper().wrap(decPrimitives);

    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] contextInfo = "contextInfo".getBytes(UTF_8);
    byte[] ciphertext = encrypter.encrypt(plaintext, contextInfo);

    assertThat(decrypter.decrypt(ciphertext, contextInfo)).isEqualTo(plaintext);

    assertThat(fakeMonitoringClient.getLogEntries()).isEmpty();
    assertThat(fakeMonitoringClient.getLogFailureEntries()).isEmpty();
  }

  @Theory
  public void monitorsWithAnnotations() throws Exception {
    FakeMonitoringClient fakeMonitoringClient = new FakeMonitoringClient();
    MutableMonitoringRegistry.globalInstance().clear();
    MutableMonitoringRegistry.globalInstance().registerMonitoringClient(fakeMonitoringClient);

    MonitoringAnnotations annotations =
        MonitoringAnnotations.newBuilder().add("annotation_name", "annotation_value").build();

    // We use two keys, to make sure that decryption logs the correct key id.
    Key privateKey1 =
        getPrivateKey(eciesAeadHkdfPrivateKey1, /*keyId=*/ 123, OutputPrefixType.TINK);
    Key publicKey1 =
        getPublicKey(
            eciesAeadHkdfPrivateKey1.getPublicKey(), /*keyId=*/ 123, OutputPrefixType.TINK);

    Key privateKey2 = getPrivateKey(eciesAeadHkdfPrivateKey2, /*keyId=*/ 234, OutputPrefixType.RAW);
    Key publicKey2 =
        getPublicKey(eciesAeadHkdfPrivateKey2.getPublicKey(), /*keyId=*/ 234, OutputPrefixType.RAW);

    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] contextInfo = "contextInfo".getBytes(UTF_8);

    // Create for each key a ciphertext. Note that encrypter1 and encrypter2 are not monitored.
    HybridEncrypt encrypter1 =
        new HybridEncryptWrapper()
            .wrap(
                TestUtil.createPrimitiveSet(
                    TestUtil.createKeyset(publicKey1), HybridEncrypt.class));
    byte[] ciphertext1 = encrypter1.encrypt(plaintext, contextInfo);
    HybridEncrypt encrypter2 =
        new HybridEncryptWrapper()
            .wrap(
                TestUtil.createPrimitiveSet(
                    TestUtil.createKeyset(publicKey2), HybridEncrypt.class));
    byte[] ciphertext2 = encrypter2.encrypt(plaintext, contextInfo);

    HybridDecrypt decrypter =
        new HybridDecryptWrapper()
            .wrap(
                TestUtil.createPrimitiveSetWithAnnotations(
                    TestUtil.createKeyset(privateKey1, privateKey2),
                    annotations,
                    HybridDecrypt.class));

    assertThat(decrypter.decrypt(ciphertext1, contextInfo)).isEqualTo(plaintext);
    assertThat(decrypter.decrypt(ciphertext2, contextInfo)).isEqualTo(plaintext);
    assertThrows(
        GeneralSecurityException.class,
        () -> decrypter.decrypt(ciphertext1, "invalid".getBytes(UTF_8)));

    List<FakeMonitoringClient.LogEntry> logEntries = fakeMonitoringClient.getLogEntries();
    assertThat(logEntries).hasSize(2);
    FakeMonitoringClient.LogEntry decEntry1 = logEntries.get(0);
    assertThat(decEntry1.getKeyId()).isEqualTo(123);
    assertThat(decEntry1.getPrimitive()).isEqualTo("hybrid_decrypt");
    assertThat(decEntry1.getApi()).isEqualTo("decrypt");
    // ciphertext1 was encrypted with key1, which has a TINK ouput prefix. This adds a 5 bytes
    // prefix to the ciphertext. This prefix is not included in getNumBytesAsInput.
    assertThat(decEntry1.getNumBytesAsInput()).isEqualTo(ciphertext1.length - 5);
    assertThat(decEntry1.getKeysetInfo().getAnnotations()).isEqualTo(annotations);

    FakeMonitoringClient.LogEntry decEntry2 = logEntries.get(1);
    assertThat(decEntry2.getKeyId()).isEqualTo(234);
    assertThat(decEntry2.getPrimitive()).isEqualTo("hybrid_decrypt");
    assertThat(decEntry2.getApi()).isEqualTo("decrypt");
    assertThat(decEntry2.getNumBytesAsInput()).isEqualTo(ciphertext2.length);
    assertThat(decEntry2.getKeysetInfo().getAnnotations()).isEqualTo(annotations);

    List<FakeMonitoringClient.LogFailureEntry> failures =
        fakeMonitoringClient.getLogFailureEntries();
    assertThat(failures).hasSize(1);
    FakeMonitoringClient.LogFailureEntry decryptFailure = failures.get(0);
    assertThat(decryptFailure.getPrimitive()).isEqualTo("hybrid_decrypt");
    assertThat(decryptFailure.getApi()).isEqualTo("decrypt");
    assertThat(decryptFailure.getKeysetInfo().getAnnotations()).isEqualTo(annotations);
  }
}
