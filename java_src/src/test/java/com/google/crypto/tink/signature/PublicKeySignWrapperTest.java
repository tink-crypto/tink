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

package com.google.crypto.tink.signature;

import static com.google.common.truth.Truth.assertThat;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.CleartextKeysetHandle;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.PrimitiveSet;
import com.google.crypto.tink.PublicKeySign;
import com.google.crypto.tink.PublicKeyVerify;
import com.google.crypto.tink.Registry;
import com.google.crypto.tink.internal.MutableMonitoringRegistry;
import com.google.crypto.tink.internal.testing.FakeMonitoringClient;
import com.google.crypto.tink.monitoring.MonitoringAnnotations;
import com.google.crypto.tink.proto.EcdsaPrivateKey;
import com.google.crypto.tink.proto.EcdsaPublicKey;
import com.google.crypto.tink.proto.EcdsaSignatureEncoding;
import com.google.crypto.tink.proto.EllipticCurveType;
import com.google.crypto.tink.proto.HashType;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.proto.KeyStatusType;
import com.google.crypto.tink.proto.Keyset;
import com.google.crypto.tink.proto.Keyset.Key;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.crypto.tink.subtle.Bytes;
import com.google.crypto.tink.testing.TestUtil;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.List;
import org.junit.BeforeClass;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

/** Unit tests for {@link PublicKeySignWrapper}. */
@RunWith(Theories.class)
public class PublicKeySignWrapperTest {

  private static EcdsaPrivateKey ecdsaPrivateKey;
  private static EcdsaPrivateKey ecdsaPrivateKey2;

  @BeforeClass
  public static void setUpClass() throws Exception {
    SignatureConfig.register();
    ecdsaPrivateKey =
        TestUtil.generateEcdsaPrivKey(
            EllipticCurveType.NIST_P521, HashType.SHA512, EcdsaSignatureEncoding.DER);
    ecdsaPrivateKey2 =
        TestUtil.generateEcdsaPrivKey(
            EllipticCurveType.NIST_P384, HashType.SHA384, EcdsaSignatureEncoding.IEEE_P1363);
  }

  private static Key getPublicKey(
      EcdsaPublicKey ecdsaPubKey, int keyId, OutputPrefixType prefixType) throws Exception {
    return TestUtil.createKey(
        TestUtil.createKeyData(
            ecdsaPubKey,
            "type.googleapis.com/google.crypto.tink.EcdsaPublicKey",
            KeyData.KeyMaterialType.ASYMMETRIC_PUBLIC),
        keyId,
        KeyStatusType.ENABLED,
        prefixType);
  }

  private static Key getPrivateKey(
      EcdsaPrivateKey ecdsaPrivKey, int keyId, OutputPrefixType prefixType) throws Exception {
    return TestUtil.createKey(
        TestUtil.createKeyData(
            ecdsaPrivKey,
            "type.googleapis.com/google.crypto.tink.EcdsaPrivateKey",
            KeyData.KeyMaterialType.ASYMMETRIC_PRIVATE),
        keyId,
        KeyStatusType.ENABLED,
        prefixType);
  }

  @Theory
  public void signRaw_canBeVerifiedByRawVerifier() throws Exception {
    Key privateKey = getPrivateKey(ecdsaPrivateKey, /*keyId=*/ 0x66AABBCC, OutputPrefixType.RAW);
    Key publicKey =
        getPublicKey(ecdsaPrivateKey.getPublicKey(), /*keyId=*/ 0x66AABBCC, OutputPrefixType.RAW);
    PublicKeySign rawSigner = Registry.getPrimitive(privateKey.getKeyData(), PublicKeySign.class);
    PublicKeyVerify rawVerifier =
        Registry.getPrimitive(publicKey.getKeyData(), PublicKeyVerify.class);

    PrimitiveSet<PublicKeySign> primitives =
        PrimitiveSet.newBuilder(PublicKeySign.class)
            .addPrimaryPrimitive(rawSigner, privateKey)
            .build();
    PublicKeySign wrappedSigner = new PublicKeySignWrapper().wrap(primitives);

    byte[] data = "data".getBytes(UTF_8);
    byte[] sig = wrappedSigner.sign(data);

    rawVerifier.verify(sig, data);
  }

  @Theory
  public void signTink_generatesSignatureWithTinkPrefix() throws Exception {
    Key privateKey = getPrivateKey(ecdsaPrivateKey, /*keyId=*/ 0x66AABBCC, OutputPrefixType.TINK);
    Key publicKey =
        getPublicKey(ecdsaPrivateKey.getPublicKey(), /*keyId=*/ 0x66AABBCC, OutputPrefixType.TINK);
    PublicKeySign rawSigner = Registry.getPrimitive(privateKey.getKeyData(), PublicKeySign.class);
    PublicKeyVerify rawVerifier =
        Registry.getPrimitive(publicKey.getKeyData(), PublicKeyVerify.class);

    PrimitiveSet<PublicKeySign> primitives =
        PrimitiveSet.newBuilder(PublicKeySign.class)
            .addPrimaryPrimitive(rawSigner, privateKey)
            .build();
    PublicKeySign wrappedSigner = new PublicKeySignWrapper().wrap(primitives);

    byte[] data = "data".getBytes(UTF_8);
    byte[] sig = wrappedSigner.sign(data);

    byte[] prefix = Arrays.copyOf(sig, 5);
    byte[] sigWithoutPrefix = Arrays.copyOfRange(sig, 5, sig.length);

    assertThat(prefix).isEqualTo(TestUtil.hexDecode("0166AABBCC"));

    rawVerifier.verify(sigWithoutPrefix, data);
  }

  @Theory
  public void signCrunchy_generatesSignatureWithCrunchyPrefix() throws Exception {
    Key privateKey =
        getPrivateKey(ecdsaPrivateKey, /*keyId=*/ 0x66AABBCC, OutputPrefixType.CRUNCHY);
    Key publicKey =
        getPublicKey(
            ecdsaPrivateKey.getPublicKey(), /*keyId=*/ 0x66AABBCC, OutputPrefixType.CRUNCHY);
    PublicKeySign rawSigner = Registry.getPrimitive(privateKey.getKeyData(), PublicKeySign.class);
    PublicKeyVerify rawVerifier =
        Registry.getPrimitive(publicKey.getKeyData(), PublicKeyVerify.class);

    PrimitiveSet<PublicKeySign> primitives =
        PrimitiveSet.newBuilder(PublicKeySign.class)
            .addPrimaryPrimitive(rawSigner, privateKey)
            .build();
    PublicKeySign wrappedSigner = new PublicKeySignWrapper().wrap(primitives);

    byte[] data = "data".getBytes(UTF_8);
    byte[] sig = wrappedSigner.sign(data);

    byte[] prefix = Arrays.copyOf(sig, 5);
    byte[] sigWithoutPrefix = Arrays.copyOfRange(sig, 5, sig.length);

    assertThat(prefix).isEqualTo(TestUtil.hexDecode("0066AABBCC"));

    rawVerifier.verify(sigWithoutPrefix, data);
  }

  @Theory
  public void signLegacy_generatesSignatureWithLegacyPrefixOfDataWithAppendedZero()
      throws Exception {
    Key privateKey = getPrivateKey(ecdsaPrivateKey, /*keyId=*/ 0x66AABBCC, OutputPrefixType.LEGACY);
    Key publicKey =
        getPublicKey(
            ecdsaPrivateKey.getPublicKey(), /*keyId=*/ 0x66AABBCC, OutputPrefixType.LEGACY);
    PublicKeySign rawSigner = Registry.getPrimitive(privateKey.getKeyData(), PublicKeySign.class);
    PublicKeyVerify rawVerifier =
        Registry.getPrimitive(publicKey.getKeyData(), PublicKeyVerify.class);

    PrimitiveSet<PublicKeySign> primitives =
        PrimitiveSet.newBuilder(PublicKeySign.class)
            .addPrimaryPrimitive(rawSigner, privateKey)
            .build();
    PublicKeySign wrappedSigner = new PublicKeySignWrapper().wrap(primitives);

    byte[] data = "data".getBytes(UTF_8);
    byte[] sig = wrappedSigner.sign(data);

    byte[] prefix = Arrays.copyOf(sig, 5);
    byte[] sigWithoutPrefix = Arrays.copyOfRange(sig, 5, sig.length);

    assertThat(prefix).isEqualTo(TestUtil.hexDecode("0066AABBCC"));

    byte[] signedData = Bytes.concat(data, TestUtil.hexDecode("00"));
    rawVerifier.verify(sigWithoutPrefix, signedData);
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
  public void verifyWrapperCanVerifySignatures(
      @FromDataPoints("outputPrefixType") OutputPrefixType prefix) throws Exception {
    PrimitiveSet<PublicKeySign> signPrimitives =
        TestUtil.createPrimitiveSet(
            TestUtil.createKeyset(getPrivateKey(ecdsaPrivateKey, /*keyId=*/ 123, prefix)),
            PublicKeySign.class);
    PublicKeySign signer = new PublicKeySignWrapper().wrap(signPrimitives);

    PrimitiveSet<PublicKeyVerify> verifyPrimitives =
        TestUtil.createPrimitiveSet(
            TestUtil.createKeyset(
                getPublicKey(ecdsaPrivateKey.getPublicKey(), /*keyId=*/ 123, prefix)),
            PublicKeyVerify.class);
    PublicKeyVerify verifier = new PublicKeyVerifyWrapper().wrap(verifyPrimitives);

    byte[] data = "data".getBytes(UTF_8);
    byte[] sig = signer.sign(data);
    verifier.verify(sig, data);
  }

  @Theory
  public void usesPrimaryToSign()
      throws Exception {
    Key key1 = getPrivateKey(ecdsaPrivateKey, /*keyId=*/ 123, OutputPrefixType.TINK);
    Key key2 = getPrivateKey(ecdsaPrivateKey2, /*keyId=*/ 234, OutputPrefixType.TINK);
    PublicKeySign signer1 = Registry.getPrimitive(key1.getKeyData(), PublicKeySign.class);
    PublicKeySign signer2 = Registry.getPrimitive(key2.getKeyData(), PublicKeySign.class);
    PrimitiveSet<PublicKeySign> signPrimitives =
        PrimitiveSet.newBuilder(PublicKeySign.class)
            .addPrimitive(signer1, key1)
            .addPrimaryPrimitive(signer2, key2)
            .build();
    PublicKeySign signer = new PublicKeySignWrapper().wrap(signPrimitives);

    PublicKeyVerify verify1 =
        new PublicKeyVerifyWrapper()
            .wrap(
                TestUtil.createPrimitiveSet(
                    TestUtil.createKeyset(
                        getPublicKey(
                            ecdsaPrivateKey.getPublicKey(), /*keyId=*/ 123, OutputPrefixType.TINK)),
                    PublicKeyVerify.class));
    PublicKeyVerify verifyPrimary =
        new PublicKeyVerifyWrapper()
            .wrap(
                TestUtil.createPrimitiveSet(
                    TestUtil.createKeyset(
                        getPublicKey(
                            ecdsaPrivateKey2.getPublicKey(),
                            /*keyId=*/ 234,
                            OutputPrefixType.TINK)),
                    PublicKeyVerify.class));

    byte[] data = "data".getBytes(UTF_8);
    byte[] sig = signer.sign(data);
    // key2 is primary. Verify works.
    verifyPrimary.verify(sig, data);
    // key1 is not primary. Verify fails.
    assertThrows(
        GeneralSecurityException.class, () -> verify1.verify(sig, data));
  }

  @Theory
  public void signWithoutPrimary_throwsNullPointerException() throws Exception {
    Key key = getPrivateKey(ecdsaPrivateKey, /*keyId=*/ 123, OutputPrefixType.TINK);
    PublicKeySign rawSigner = Registry.getPrimitive(key.getKeyData(), PublicKeySign.class);
    PrimitiveSet<PublicKeySign> signPrimitives =
        PrimitiveSet.newBuilder(PublicKeySign.class).addPrimitive(rawSigner, key).build();
    PublicKeySign signer = new PublicKeySignWrapper().wrap(signPrimitives);

    byte[] data = "data".getBytes(UTF_8);
    // This usually should not happen, since PublicKeySignWrapper is generated by KeysetHandle,
    // which validates the keyset. See primitiveFromKeysetHandleWithoutPrimary_throws.
    assertThrows(NullPointerException.class, () -> signer.sign(data));
  }

  @Theory
  public void primitiveFromKeysetHandleWithoutPrimary_throws() throws Exception {
    Keyset keysetWithoutPrimary =
        Keyset.newBuilder()
            .addKey(getPrivateKey(ecdsaPrivateKey, /*keyId=*/ 123, OutputPrefixType.TINK))
            .build();
    KeysetHandle keysetHandle = CleartextKeysetHandle.fromKeyset(keysetWithoutPrimary);
    assertThrows(
        GeneralSecurityException.class, () -> keysetHandle.getPrimitive(PublicKeySign.class));
  }

  @Theory
  public void doesNotMonitorWithoutAnnotations() throws Exception {
    FakeMonitoringClient fakeMonitoringClient = new FakeMonitoringClient();
    MutableMonitoringRegistry.globalInstance().clear();
    MutableMonitoringRegistry.globalInstance().registerMonitoringClient(fakeMonitoringClient);

    PrimitiveSet<PublicKeySign> signPrimitives =
        TestUtil.createPrimitiveSet(
            TestUtil.createKeyset(
                getPrivateKey(ecdsaPrivateKey, /*keyId=*/ 123, OutputPrefixType.TINK)),
            PublicKeySign.class);
    PublicKeySign signer = new PublicKeySignWrapper().wrap(signPrimitives);

    byte[] data = "data".getBytes(UTF_8);
    signer.sign(data);

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
    Key privateKey = getPrivateKey(ecdsaPrivateKey, /*keyId=*/ 123, OutputPrefixType.TINK);
    Key privateKey2 = getPrivateKey(ecdsaPrivateKey2, /*keyId=*/ 234, OutputPrefixType.LEGACY);

    PublicKeySign signer =
        new PublicKeySignWrapper()
            .wrap(
                TestUtil.createPrimitiveSetWithAnnotations(
                    TestUtil.createKeyset(privateKey), annotations, PublicKeySign.class));
    PublicKeySign signer2 =
        new PublicKeySignWrapper()
            .wrap(
                TestUtil.createPrimitiveSetWithAnnotations(
                    TestUtil.createKeyset(privateKey2), annotations, PublicKeySign.class));
    byte[] data = "data".getBytes(UTF_8);
    signer.sign(data);
    signer2.sign(data);

    List<FakeMonitoringClient.LogEntry> logEntries = fakeMonitoringClient.getLogEntries();
    assertThat(logEntries).hasSize(2);
    FakeMonitoringClient.LogEntry sign1Entry = logEntries.get(0);
    assertThat(sign1Entry.getKeyId()).isEqualTo(123);
    assertThat(sign1Entry.getPrimitive()).isEqualTo("public_key_sign");
    assertThat(sign1Entry.getApi()).isEqualTo("sign");
    assertThat(sign1Entry.getNumBytesAsInput()).isEqualTo(data.length);
    assertThat(sign1Entry.getKeysetInfo().getAnnotations()).isEqualTo(annotations);

    FakeMonitoringClient.LogEntry sign2Entry = logEntries.get(1);
    assertThat(sign2Entry.getKeyId()).isEqualTo(234);
    assertThat(sign2Entry.getPrimitive()).isEqualTo("public_key_sign");
    assertThat(sign2Entry.getApi()).isEqualTo("sign");
    // LEGACY adds an extra byte to data before it is signed.
    assertThat(sign2Entry.getNumBytesAsInput()).isEqualTo(data.length + 1);
    assertThat(sign2Entry.getKeysetInfo().getAnnotations()).isEqualTo(annotations);
  }

  private static class AlwaysFailingPublicKeySign implements PublicKeySign {
    @Override
    public byte[] sign(byte[] data) throws GeneralSecurityException {
      throw new GeneralSecurityException("fail");
    }
  }

  @Theory
  public void testAlwaysFailingPublicKeySignWithAnnotations_hasMonitoring() throws Exception {
    FakeMonitoringClient fakeMonitoringClient = new FakeMonitoringClient();
    MutableMonitoringRegistry.globalInstance().clear();
    MutableMonitoringRegistry.globalInstance().registerMonitoringClient(fakeMonitoringClient);

    MonitoringAnnotations annotations =
        MonitoringAnnotations.newBuilder().add("annotation_name", "annotation_value").build();
    PrimitiveSet<PublicKeySign> primitives =
        PrimitiveSet.newBuilder(PublicKeySign.class)
            .setAnnotations(annotations)
            .addPrimaryPrimitive(
                new AlwaysFailingPublicKeySign(),
                getPrivateKey(ecdsaPrivateKey, /*keyId=*/ 123, OutputPrefixType.TINK))
            .build();
    PublicKeySign signer = new PublicKeySignWrapper().wrap(primitives);

    byte[] data = "data".getBytes(UTF_8);
    assertThrows(GeneralSecurityException.class, () -> signer.sign(data));

    assertThat(fakeMonitoringClient.getLogEntries()).isEmpty();

    List<FakeMonitoringClient.LogFailureEntry> failures =
        fakeMonitoringClient.getLogFailureEntries();
    assertThat(failures).hasSize(1);
    FakeMonitoringClient.LogFailureEntry signFailure = failures.get(0);
    assertThat(signFailure.getPrimitive()).isEqualTo("public_key_sign");
    assertThat(signFailure.getApi()).isEqualTo("sign");
    assertThat(signFailure.getKeysetInfo().getPrimaryKeyId()).isEqualTo(123);
    assertThat(signFailure.getKeysetInfo().getAnnotations()).isEqualTo(annotations);
  }
}
