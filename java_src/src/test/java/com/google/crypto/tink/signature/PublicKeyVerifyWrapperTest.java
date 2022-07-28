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
import com.google.crypto.tink.proto.Keyset.Key;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.crypto.tink.subtle.Bytes;
import com.google.crypto.tink.testing.TestUtil;
import java.security.GeneralSecurityException;
import java.util.List;
import org.junit.BeforeClass;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

/** Unit tests for {@link PublicKeyVerifyWrapper}. */
@RunWith(Theories.class)
public class PublicKeyVerifyWrapperTest {

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
            KeyData.KeyMaterialType.ASYMMETRIC_PUBLIC),
        keyId,
        KeyStatusType.ENABLED,
        prefixType);
  }

  @Theory
  public void verifyRaw_worksOnRawPrefixedSignature() throws Exception {
    Key privateKey = getPrivateKey(ecdsaPrivateKey, /*keyId=*/ 0x66AABBCC, OutputPrefixType.RAW);
    Key publicKey =
        getPublicKey(ecdsaPrivateKey.getPublicKey(), /*keyId=*/ 0x66AABBCC, OutputPrefixType.RAW);
    PublicKeySign rawSigner = Registry.getPrimitive(privateKey.getKeyData(), PublicKeySign.class);
    PublicKeyVerify rawVerifier =
        Registry.getPrimitive(publicKey.getKeyData(), PublicKeyVerify.class);

    PrimitiveSet<PublicKeyVerify> primitives =
        PrimitiveSet.newBuilder(PublicKeyVerify.class)
            .addPrimaryPrimitive(rawVerifier, publicKey)
            .build();
    PublicKeyVerify wrappedVerifier = new PublicKeyVerifyWrapper().wrap(primitives);

    byte[] data = "data".getBytes(UTF_8);
    byte[] sig = rawSigner.sign(data);

    wrappedVerifier.verify(sig, data);

    byte[] sigWithTinkPrefix = Bytes.concat(TestUtil.hexDecode("0166AABBCC"), sig);
    assertThrows(
        GeneralSecurityException.class, () -> wrappedVerifier.verify(sigWithTinkPrefix, data));
    assertThrows(
        GeneralSecurityException.class,
        () -> wrappedVerifier.verify(sig, "invalid".getBytes(UTF_8)));
    assertThrows(
        GeneralSecurityException.class,
        () -> wrappedVerifier.verify("invalid".getBytes(UTF_8), data));
    assertThrows(
        GeneralSecurityException.class, () -> wrappedVerifier.verify("".getBytes(UTF_8), data));
  }

  @Theory
  public void verifyTink_worksOnTinkPrefixedSignature() throws Exception {
    Key privateKey = getPrivateKey(ecdsaPrivateKey, /*keyId=*/ 0x66AABBCC, OutputPrefixType.TINK);
    Key publicKey =
        getPublicKey(ecdsaPrivateKey.getPublicKey(), /*keyId=*/ 0x66AABBCC, OutputPrefixType.TINK);
    PublicKeySign rawSigner = Registry.getPrimitive(privateKey.getKeyData(), PublicKeySign.class);
    PublicKeyVerify rawVerifier =
        Registry.getPrimitive(publicKey.getKeyData(), PublicKeyVerify.class);

    PrimitiveSet<PublicKeyVerify> primitives =
        PrimitiveSet.newBuilder(PublicKeyVerify.class)
            .addPrimaryPrimitive(rawVerifier, publicKey)
            .build();
    PublicKeyVerify wrappedVerifier = new PublicKeyVerifyWrapper().wrap(primitives);

    byte[] data = "data".getBytes(UTF_8);
    byte[] sig = rawSigner.sign(data);
    byte[] sigWithTinkPrefix = Bytes.concat(TestUtil.hexDecode("0166AABBCC"), sig);
    wrappedVerifier.verify(sigWithTinkPrefix, data);

    byte[] sigWithCrunchyPrefix = Bytes.concat(TestUtil.hexDecode("0066AABBCC"), sig);
    assertThrows(
        GeneralSecurityException.class, () -> wrappedVerifier.verify(sigWithCrunchyPrefix, data));
    assertThrows(GeneralSecurityException.class, () -> wrappedVerifier.verify(sig, data));
    assertThrows(
        GeneralSecurityException.class,
        () -> wrappedVerifier.verify(sigWithTinkPrefix, "invalid".getBytes(UTF_8)));
    assertThrows(
        GeneralSecurityException.class,
        () -> wrappedVerifier.verify("invalid".getBytes(UTF_8), data));
    assertThrows(
        GeneralSecurityException.class, () -> wrappedVerifier.verify("".getBytes(UTF_8), data));
  }

  @Theory
  public void verifyCrunchy_worksOnCrunchyPrefixedSignature() throws Exception {
    Key privateKey =
        getPrivateKey(ecdsaPrivateKey, /*keyId=*/ 0x66AABBCC, OutputPrefixType.CRUNCHY);
    Key publicKey =
        getPublicKey(
            ecdsaPrivateKey.getPublicKey(), /*keyId=*/ 0x66AABBCC, OutputPrefixType.CRUNCHY);
    PublicKeySign rawSigner = Registry.getPrimitive(privateKey.getKeyData(), PublicKeySign.class);
    PublicKeyVerify rawVerifier =
        Registry.getPrimitive(publicKey.getKeyData(), PublicKeyVerify.class);

    PrimitiveSet<PublicKeyVerify> primitives =
        PrimitiveSet.newBuilder(PublicKeyVerify.class)
            .addPrimaryPrimitive(rawVerifier, publicKey)
            .build();
    PublicKeyVerify wrappedVerifier = new PublicKeyVerifyWrapper().wrap(primitives);

    byte[] data = "data".getBytes(UTF_8);
    byte[] sig = rawSigner.sign(data);
    byte[] sigWithCrunchyPrefix = Bytes.concat(TestUtil.hexDecode("0066AABBCC"), sig);
    wrappedVerifier.verify(sigWithCrunchyPrefix, data);

    byte[] sigWithTinkPrefix = Bytes.concat(TestUtil.hexDecode("0166AABBCC"), sig);
    assertThrows(
        GeneralSecurityException.class, () -> wrappedVerifier.verify(sigWithTinkPrefix, data));
    assertThrows(GeneralSecurityException.class, () -> wrappedVerifier.verify(sig, data));
    assertThrows(
        GeneralSecurityException.class,
        () -> wrappedVerifier.verify(sigWithCrunchyPrefix, "invalid".getBytes(UTF_8)));
    assertThrows(
        GeneralSecurityException.class,
        () -> wrappedVerifier.verify("invalid".getBytes(UTF_8), data));
    assertThrows(
        GeneralSecurityException.class, () -> wrappedVerifier.verify("".getBytes(UTF_8), data));
  }

  @Theory
  public void verifyLegacy_worksOnLegacyPrefixedSignatureOfDataWithAppendedZero()
      throws Exception {
    Key privateKey =
        getPrivateKey(ecdsaPrivateKey, /*keyId=*/ 0x66AABBCC, OutputPrefixType.LEGACY);
    Key publicKey =
        getPublicKey(
            ecdsaPrivateKey.getPublicKey(), /*keyId=*/ 0x66AABBCC, OutputPrefixType.LEGACY);
    PublicKeySign rawSigner = Registry.getPrimitive(privateKey.getKeyData(), PublicKeySign.class);
    PublicKeyVerify rawVerifier =
        Registry.getPrimitive(publicKey.getKeyData(), PublicKeyVerify.class);

    PrimitiveSet<PublicKeyVerify> primitives =
        PrimitiveSet.newBuilder(PublicKeyVerify.class)
            .addPrimaryPrimitive(rawVerifier, publicKey)
            .build();
    PublicKeyVerify wrappedVerifier = new PublicKeyVerifyWrapper().wrap(primitives);

    byte[] data = "data".getBytes(UTF_8);
    byte[] dataToSign = Bytes.concat(data, TestUtil.hexDecode("00"));
    byte[] legacySig =
        Bytes.concat(TestUtil.hexDecode("0066AABBCC"), rawSigner.sign(dataToSign));
    wrappedVerifier.verify(legacySig, data);

    assertThrows(
        GeneralSecurityException.class, () -> wrappedVerifier.verify(legacySig, dataToSign));

    byte[] crunchySig = Bytes.concat(TestUtil.hexDecode("0066AABBCC"), rawSigner.sign(data));
    assertThrows(
        GeneralSecurityException.class, () -> wrappedVerifier.verify(crunchySig, data));
    assertThrows(
        GeneralSecurityException.class,
        () -> wrappedVerifier.verify(legacySig, "invalid".getBytes(UTF_8)));
    assertThrows(
        GeneralSecurityException.class,
        () -> wrappedVerifier.verify("invalid".getBytes(UTF_8), data));
    assertThrows(
        GeneralSecurityException.class, () -> wrappedVerifier.verify("".getBytes(UTF_8), data));
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
  public void canVerifySignaturesBySignWrapper(
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
  public void failsIfSignedByOtherKeyEvenIfKeyIdsAreEqual(
      @FromDataPoints("outputPrefixType") OutputPrefixType prefix) throws Exception {
    PrimitiveSet<PublicKeySign> signPrimitives2 =
        TestUtil.createPrimitiveSet(
            TestUtil.createKeyset(getPrivateKey(ecdsaPrivateKey2, /*keyId=*/ 123, prefix)),
            PublicKeySign.class);
    PublicKeySign signer2 = new PublicKeySignWrapper().wrap(signPrimitives2);

    PrimitiveSet<PublicKeyVerify> verifyPrimitives =
        TestUtil.createPrimitiveSet(
            TestUtil.createKeyset(
                getPublicKey(ecdsaPrivateKey.getPublicKey(), /*keyId=*/ 123, prefix)),
            PublicKeyVerify.class);
    PublicKeyVerify verifier = new PublicKeyVerifyWrapper().wrap(verifyPrimitives);

    byte[] data = "data".getBytes(UTF_8);
    byte[] sig = signer2.sign(data);
    assertThrows(
        GeneralSecurityException.class, () -> verifier.verify(sig, data));
  }

  @Theory
  public void verifyWorksIfSignatureIsValidForAnyPrimitiveInThePrimitiveSet(
      @FromDataPoints("outputPrefixType") OutputPrefixType prefix1,
      @FromDataPoints("outputPrefixType") OutputPrefixType prefix2)
      throws Exception {
    PublicKeySign signer1 =
        new PublicKeySignWrapper()
            .wrap(
                TestUtil.createPrimitiveSet(
                    TestUtil.createKeyset(getPrivateKey(ecdsaPrivateKey, /*keyId=*/ 123, prefix1)),
                    PublicKeySign.class));
    PublicKeySign signer2 =
        new PublicKeySignWrapper()
            .wrap(
                TestUtil.createPrimitiveSet(
                    TestUtil.createKeyset(getPrivateKey(ecdsaPrivateKey2, /*keyId=*/ 234, prefix2)),
                    PublicKeySign.class));

    PrimitiveSet<PublicKeyVerify> verifyPrimitives =
        TestUtil.createPrimitiveSet(
            TestUtil.createKeyset(
                getPublicKey(ecdsaPrivateKey.getPublicKey(), /*keyId=*/ 123, prefix1),
                getPublicKey(ecdsaPrivateKey2.getPublicKey(), /*keyId=*/ 234, prefix2)),
            PublicKeyVerify.class);
    PublicKeyVerify verifier = new PublicKeyVerifyWrapper().wrap(verifyPrimitives);

    byte[] data = "data".getBytes(UTF_8);
    byte[] sig1 = signer1.sign(data);
    byte[] sig2 = signer2.sign(data);
    verifier.verify(sig1, data);
    verifier.verify(sig2, data);
  }

  @Theory
  public void noPrimary_verifyWorks() throws Exception {
    PublicKeySign signer =
        new PublicKeySignWrapper()
            .wrap(
                TestUtil.createPrimitiveSet(
                    TestUtil.createKeyset(
                        getPrivateKey(ecdsaPrivateKey, /*keyId=*/ 123, OutputPrefixType.TINK)),
                    PublicKeySign.class));
    byte[] data = "data".getBytes(UTF_8);
    byte[] sig = signer.sign(data);

    Key publicKey =
        getPublicKey(ecdsaPrivateKey.getPublicKey(), /*keyId=*/ 123, OutputPrefixType.TINK);
    PublicKeyVerify verify = Registry.getPrimitive(publicKey.getKeyData(), PublicKeyVerify.class);
    PrimitiveSet<PublicKeyVerify> verifyPrimitivesWithoutPrimary =
        PrimitiveSet.newBuilder(PublicKeyVerify.class)
            .addPrimitive(verify, publicKey)
            .build();
    PublicKeyVerify wrappedVerifier =
        new PublicKeyVerifyWrapper().wrap(verifyPrimitivesWithoutPrimary);

    wrappedVerifier.verify(sig, data);
  }

  @DataPoints("nonRawOutputPrefixType")
  public static final OutputPrefixType[] NON_RAW_OUTPUT_PREFIX_TYPES =
      new OutputPrefixType[] {
        OutputPrefixType.LEGACY, OutputPrefixType.CRUNCHY, OutputPrefixType.TINK
      };

  @Theory
  public void nonRawKeyPairWithTwoDifferentKeyIds_verifyFails(
      @FromDataPoints("nonRawOutputPrefixType") OutputPrefixType prefix) throws Exception {
    PrimitiveSet<PublicKeySign> signPrimitives =
        TestUtil.createPrimitiveSet(
            TestUtil.createKeyset(getPrivateKey(ecdsaPrivateKey, /*keyId=*/ 123, prefix)),
            PublicKeySign.class);
    PublicKeySign signer = new PublicKeySignWrapper().wrap(signPrimitives);

    PrimitiveSet<PublicKeyVerify> verifyPrimitives =
        TestUtil.createPrimitiveSet(
            TestUtil.createKeyset(
                getPublicKey(ecdsaPrivateKey.getPublicKey(), /*keyId=*/ 234, prefix)),
            PublicKeyVerify.class);
    PublicKeyVerify verifier = new PublicKeyVerifyWrapper().wrap(verifyPrimitives);

    byte[] data = "data".getBytes(UTF_8);
    byte[] sig = signer.sign(data);

    assertThrows(GeneralSecurityException.class, () -> verifier.verify(sig, data));
  }

  @Theory
  public void rawKeyPairWithTwoDifferentKeyIds_works() throws Exception {
    PrimitiveSet<PublicKeySign> signPrimitives =
        TestUtil.createPrimitiveSet(
            TestUtil.createKeyset(
                getPrivateKey(ecdsaPrivateKey, /*keyId=*/ 123, OutputPrefixType.RAW)),
            PublicKeySign.class);
    PublicKeySign signer = new PublicKeySignWrapper().wrap(signPrimitives);

    PrimitiveSet<PublicKeyVerify> verifyPrimitives =
        TestUtil.createPrimitiveSet(
            TestUtil.createKeyset(
                getPublicKey(ecdsaPrivateKey.getPublicKey(), /*keyId=*/ 234, OutputPrefixType.RAW)),
            PublicKeyVerify.class);
    PublicKeyVerify verifier = new PublicKeyVerifyWrapper().wrap(verifyPrimitives);

    byte[] data = "data".getBytes(UTF_8);
    byte[] sig = signer.sign(data);
    verifier.verify(sig, data);
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

    PrimitiveSet<PublicKeyVerify> verifyPrimitives =
        TestUtil.createPrimitiveSet(
            TestUtil.createKeyset(
                getPublicKey(
                    ecdsaPrivateKey.getPublicKey(), /*keyId=*/ 123, OutputPrefixType.TINK)),
            PublicKeyVerify.class);
    PublicKeyVerify verifier = new PublicKeyVerifyWrapper().wrap(verifyPrimitives);

    byte[] data = "data".getBytes(UTF_8);
    byte[] sig = signer.sign(data);
    verifier.verify(sig, data);

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
    Key publicKey =
        getPublicKey(ecdsaPrivateKey.getPublicKey(), /*keyId=*/ 123, OutputPrefixType.TINK);

    Key privateKey2 = getPrivateKey(ecdsaPrivateKey, /*keyId=*/ 234, OutputPrefixType.LEGACY);
    Key publicKey2 =
        getPublicKey(ecdsaPrivateKey.getPublicKey(), /*keyId=*/ 234, OutputPrefixType.LEGACY);

    byte[] data = "data".getBytes(UTF_8);

    // Create for each key a signature. Note that signer and signer2 are not monitored.
    PublicKeySign signer =
        new PublicKeySignWrapper()
            .wrap(
                TestUtil.createPrimitiveSet(
                    TestUtil.createKeyset(privateKey), PublicKeySign.class));
    byte[] sig = signer.sign(data);
    PublicKeySign signer2 =
        new PublicKeySignWrapper()
            .wrap(
                TestUtil.createPrimitiveSet(
                    TestUtil.createKeyset(privateKey2), PublicKeySign.class));
    byte[] sig2 = signer2.sign(data);

    PublicKeyVerify verifier =
        new PublicKeyVerifyWrapper()
            .wrap(
                TestUtil.createPrimitiveSetWithAnnotations(
                    TestUtil.createKeyset(publicKey, publicKey2),
                    annotations,
                    PublicKeyVerify.class));

    verifier.verify(sig, data);
    verifier.verify(sig2, data);
    assertThrows(
        GeneralSecurityException.class, () -> verifier.verify("invalid".getBytes(UTF_8), data));

    List<FakeMonitoringClient.LogEntry> logEntries = fakeMonitoringClient.getLogEntries();
    assertThat(logEntries).hasSize(2);
    FakeMonitoringClient.LogEntry verify1Entry = logEntries.get(0);
    assertThat(verify1Entry.getKeyId()).isEqualTo(123);
    assertThat(verify1Entry.getPrimitive()).isEqualTo("public_key_verify");
    assertThat(verify1Entry.getApi()).isEqualTo("verify");
    assertThat(verify1Entry.getNumBytesAsInput()).isEqualTo(data.length);
    assertThat(verify1Entry.getKeysetInfo().getAnnotations()).isEqualTo(annotations);

    FakeMonitoringClient.LogEntry verify2Entry = logEntries.get(1);
    assertThat(verify2Entry.getKeyId()).isEqualTo(234);
    assertThat(verify2Entry.getPrimitive()).isEqualTo("public_key_verify");
    assertThat(verify2Entry.getApi()).isEqualTo("verify");
    // LEGACY adds an extra byte to data before it is signed.
    assertThat(verify2Entry.getNumBytesAsInput()).isEqualTo(data.length + 1);
    assertThat(verify2Entry.getKeysetInfo().getAnnotations()).isEqualTo(annotations);

    List<FakeMonitoringClient.LogFailureEntry> failures =
        fakeMonitoringClient.getLogFailureEntries();
    assertThat(failures).hasSize(1);
    FakeMonitoringClient.LogFailureEntry verifyFailure = failures.get(0);
    assertThat(verifyFailure.getPrimitive()).isEqualTo("public_key_verify");
    assertThat(verifyFailure.getApi()).isEqualTo("verify");
    assertThat(verifyFailure.getKeysetInfo().getAnnotations()).isEqualTo(annotations);
  }
}
