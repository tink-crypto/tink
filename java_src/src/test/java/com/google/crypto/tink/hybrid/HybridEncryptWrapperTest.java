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
import com.google.crypto.tink.testing.TestUtil;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.List;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

/** Tests for HybridEncryptWrapper. */
@RunWith(Theories.class)
public class HybridEncryptWrapperTest {

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
  public void encryptRaw_worksWithRawDecrypter() throws Exception {
    Key privateKey =
        getPrivateKey(eciesAeadHkdfPrivateKey1, /*keyId=*/ 0x66AABBCC, OutputPrefixType.RAW);
    Key publicKey =
        getPublicKey(
            eciesAeadHkdfPrivateKey1.getPublicKey(), /*keyId=*/ 0x66AABBCC, OutputPrefixType.RAW);

    HybridEncrypt rawEncrypter = Registry.getPrimitive(publicKey.getKeyData(), HybridEncrypt.class);
    HybridDecrypt rawDecrypter =
        Registry.getPrimitive(privateKey.getKeyData(), HybridDecrypt.class);

    PrimitiveSet<HybridEncrypt> primitives =
        PrimitiveSet.newBuilder(HybridEncrypt.class)
            .addPrimaryPrimitive(rawEncrypter, publicKey)
            .build();
    HybridEncrypt wrappedEncrypter = new HybridEncryptWrapper().wrap(primitives);

    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] contextInfo = "contextInfo".getBytes(UTF_8);

    byte[] ciphertext = wrappedEncrypter.encrypt(plaintext, contextInfo);
    assertThat(rawDecrypter.decrypt(ciphertext, contextInfo)).isEqualTo(plaintext);
  }

  @Test
  public void encryptNonRaw_addsPrefix() throws Exception {
    Key privateKey =
        getPrivateKey(eciesAeadHkdfPrivateKey1, /*keyId=*/ 0x66AABBCC, OutputPrefixType.TINK);
    Key publicKey =
        getPublicKey(
            eciesAeadHkdfPrivateKey1.getPublicKey(), /*keyId=*/ 0x66AABBCC, OutputPrefixType.TINK);

    HybridEncrypt rawEncrypter = Registry.getPrimitive(publicKey.getKeyData(), HybridEncrypt.class);
    HybridDecrypt rawDecrypter =
        Registry.getPrimitive(privateKey.getKeyData(), HybridDecrypt.class);

    PrimitiveSet<HybridEncrypt> primitives =
        PrimitiveSet.newBuilder(HybridEncrypt.class)
            .addPrimaryPrimitive(rawEncrypter, publicKey)
            .build();
    HybridEncrypt wrappedEncrypter = new HybridEncryptWrapper().wrap(primitives);

    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] contextInfo = "contextInfo".getBytes(UTF_8);

    byte[] ciphertext = wrappedEncrypter.encrypt(plaintext, contextInfo);

    byte[] prefix = Arrays.copyOf(ciphertext, 5);
    byte[] ciphertextWithoutPrefix = Arrays.copyOfRange(ciphertext, 5, ciphertext.length);

    assertThat(prefix).isEqualTo(TestUtil.hexDecode("0166AABBCC"));

    assertThat(rawDecrypter.decrypt(ciphertextWithoutPrefix, contextInfo)).isEqualTo(plaintext);
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
  public void encrypt_decryptWrapperCanDecrypt(
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
  public void encrypt_usesPrimary() throws Exception {
    Key key1 =
        getPublicKey(
            eciesAeadHkdfPrivateKey1.getPublicKey(), /*keyId=*/ 123, OutputPrefixType.TINK);
    Key key2 =
        getPublicKey(
            eciesAeadHkdfPrivateKey2.getPublicKey(), /*keyId=*/ 234, OutputPrefixType.TINK);
    HybridEncrypt encrypter1 = Registry.getPrimitive(key1.getKeyData(), HybridEncrypt.class);
    HybridEncrypt encrypter2 = Registry.getPrimitive(key2.getKeyData(), HybridEncrypt.class);
    PrimitiveSet<HybridEncrypt> encryptPrimitives =
        PrimitiveSet.newBuilder(HybridEncrypt.class)
            .addPrimitive(encrypter1, key1)
            .addPrimaryPrimitive(encrypter2, key2)
            .build();
    HybridEncrypt encrypter = new HybridEncryptWrapper().wrap(encryptPrimitives);

    HybridDecrypt decrypter1 =
        new HybridDecryptWrapper()
            .wrap(
                TestUtil.createPrimitiveSet(
                    TestUtil.createKeyset(
                        getPrivateKey(
                            eciesAeadHkdfPrivateKey1, /*keyId=*/ 123, OutputPrefixType.TINK)),
                    HybridDecrypt.class));
    HybridDecrypt decrypter2 =
        new HybridDecryptWrapper()
            .wrap(
                TestUtil.createPrimitiveSet(
                    TestUtil.createKeyset(
                        getPrivateKey(
                            eciesAeadHkdfPrivateKey2,
                            /*keyId=*/ 234,
                            OutputPrefixType.TINK)),
                    HybridDecrypt.class));

    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] contextInfo = "contextInfo".getBytes(UTF_8);

    byte[] ciphertext = encrypter.encrypt(plaintext, contextInfo);

    // key2 is primary. Decrypt works.
    assertThat(decrypter2.decrypt(ciphertext, contextInfo)).isEqualTo(plaintext);
    // key1 is not primary. Decrypt fails.
    assertThrows(
        GeneralSecurityException.class, () -> decrypter1.decrypt(ciphertext, contextInfo));
  }

  @Theory
  public void encryptWithoutPrimary_throws() throws Exception {
    Key key =
        getPublicKey(
            eciesAeadHkdfPrivateKey1.getPublicKey(), /*keyId=*/ 123, OutputPrefixType.TINK);
    HybridEncrypt encrypter = Registry.getPrimitive(key.getKeyData(), HybridEncrypt.class);
    PrimitiveSet<HybridEncrypt> primitivesWithoutPrimary =
        PrimitiveSet.newBuilder(HybridEncrypt.class)
            .addPrimitive(encrypter, key)
            .build();
    HybridEncrypt encrypterWithoutPrimary =
        new HybridEncryptWrapper().wrap(primitivesWithoutPrimary);

    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] contextInfo = "contextInfo".getBytes(UTF_8);
    assertThrows(
        GeneralSecurityException.class,
        () -> encrypterWithoutPrimary.encrypt(plaintext, contextInfo));
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

    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] contextInfo = "contextInfo".getBytes(UTF_8);
    byte[] unused = encrypter.encrypt(plaintext, contextInfo);

    assertThat(fakeMonitoringClient.getLogEntries()).isEmpty();
    assertThat(fakeMonitoringClient.getLogFailureEntries()).isEmpty();
  }

  @Theory
  public void monitorsWithAnnotations() throws Exception {
    FakeMonitoringClient fakeMonitoringClient = new FakeMonitoringClient();
    MutableMonitoringRegistry.globalInstance().clear();
    MutableMonitoringRegistry.globalInstance().registerMonitoringClient(fakeMonitoringClient);

    Key publicKey1 =
        getPublicKey(
            eciesAeadHkdfPrivateKey1.getPublicKey(), /*keyId=*/ 123, OutputPrefixType.TINK);
    Key publicKey2 =
        getPublicKey(eciesAeadHkdfPrivateKey1.getPublicKey(), /*keyId=*/ 234, OutputPrefixType.RAW);

    MonitoringAnnotations annotations =
        MonitoringAnnotations.newBuilder().add("annotation_name", "annotation_value").build();
    HybridEncrypt encrypter =
        new HybridEncryptWrapper()
            .wrap(
                TestUtil.createPrimitiveSetWithAnnotations(
                    TestUtil.createKeyset(publicKey1, publicKey2),
                    annotations,
                    HybridEncrypt.class));

    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] contextInfo = "contextInfo".getBytes(UTF_8);
    byte[] unused = encrypter.encrypt(plaintext, contextInfo);

    List<FakeMonitoringClient.LogEntry> logEntries = fakeMonitoringClient.getLogEntries();
    assertThat(logEntries).hasSize(1);
    FakeMonitoringClient.LogEntry encEntry = logEntries.get(0);
    assertThat(encEntry.getKeyId()).isEqualTo(123);
    assertThat(encEntry.getPrimitive()).isEqualTo("hybrid_encrypt");
    assertThat(encEntry.getApi()).isEqualTo("encrypt");
    assertThat(encEntry.getNumBytesAsInput()).isEqualTo(plaintext.length);
    assertThat(encEntry.getKeysetInfo().getAnnotations()).isEqualTo(annotations);
  }

  private static class AlwaysFailingHybridEncrypt implements HybridEncrypt {
    @Override
    public byte[] encrypt(byte[] plaintext, byte[] contextInfo) throws GeneralSecurityException {
      throw new GeneralSecurityException("fail");
    }
  }

  @Theory
  public void testAlwaysFailingHybridEncryptWithAnnotations_hasMonitoring() throws Exception {
    FakeMonitoringClient fakeMonitoringClient = new FakeMonitoringClient();
    MutableMonitoringRegistry.globalInstance().clear();
    MutableMonitoringRegistry.globalInstance().registerMonitoringClient(fakeMonitoringClient);

    MonitoringAnnotations annotations =
        MonitoringAnnotations.newBuilder().add("annotation_name", "annotation_value").build();
    PrimitiveSet<HybridEncrypt> primitives =
        PrimitiveSet.newBuilder(HybridEncrypt.class)
            .setAnnotations(annotations)
            .addPrimaryPrimitive(
                new AlwaysFailingHybridEncrypt(),
                getPublicKey(
                    eciesAeadHkdfPrivateKey1.getPublicKey(), /*keyId=*/ 123, OutputPrefixType.TINK))
            .build();
    HybridEncrypt encrypter = new HybridEncryptWrapper().wrap(primitives);

    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] contextInfo = "contextInfo".getBytes(UTF_8);
    assertThrows(GeneralSecurityException.class, () -> encrypter.encrypt(plaintext, contextInfo));

    assertThat(fakeMonitoringClient.getLogEntries()).isEmpty();

    List<FakeMonitoringClient.LogFailureEntry> failures =
        fakeMonitoringClient.getLogFailureEntries();
    assertThat(failures).hasSize(1);
    FakeMonitoringClient.LogFailureEntry encryptFailure = failures.get(0);
    assertThat(encryptFailure.getPrimitive()).isEqualTo("hybrid_encrypt");
    assertThat(encryptFailure.getApi()).isEqualTo("encrypt");
    assertThat(encryptFailure.getKeysetInfo().getPrimaryKeyId()).isEqualTo(123);
    assertThat(encryptFailure.getKeysetInfo().getAnnotations()).isEqualTo(annotations);
  }
}
