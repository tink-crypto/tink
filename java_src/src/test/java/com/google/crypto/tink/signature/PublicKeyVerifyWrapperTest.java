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

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.PrimitiveSet;
import com.google.crypto.tink.PublicKeySign;
import com.google.crypto.tink.PublicKeyVerify;
import com.google.crypto.tink.Registry;
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
}
