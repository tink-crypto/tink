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

package com.google.crypto.tink.jwt;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.fail;

import com.google.crypto.tink.KeyTemplate;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.PrimitiveSet;
import com.google.crypto.tink.proto.KeyStatusType;
import com.google.crypto.tink.proto.Keyset;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.crypto.tink.subtle.EllipticCurves;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECParameterSpec;
import java.time.Clock;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import junitparams.JUnitParamsRunner;
import junitparams.Parameters;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

/** Tests for JwtSignKeyverifyWrapper. */
@RunWith(JUnitParamsRunner.class)
public class JwtPublicKeySignWrapperTest {
  private final JwtPublicKeySignWrapper signWrapper = new JwtPublicKeySignWrapper();
  private final JwtPublicKeyVerifyWrapper verifyWrapper = new JwtPublicKeyVerifyWrapper();

  private static Object[] parametersCurvesAndAlgos() {
    return new Object[] {
      new Object[] {EllipticCurves.getNistP256Params(), "ES256"},
      new Object[] {EllipticCurves.getNistP384Params(), "ES384"},
      new Object[] {EllipticCurves.getNistP521Params(), "ES512"},
    };
  }

  private static Object[] parametersPssAlgosAndSizes() {
    return new Object[] {
      new Object[] {"PS256", 2048},
      new Object[] {"PS256", 3072},
      new Object[] {"PS256", 4098},
      new Object[] {"PS384", 2048},
      new Object[] {"PS384", 3072},
      new Object[] {"PS512", 3072},
      new Object[] {"PS512", 4098},
    };
  }

  private static Object[] parametersPkcs1AlgosAndSizes() {
    return new Object[] {
      new Object[] {"RS256", 2048},
      new Object[] {"RS256", 3072},
      new Object[] {"RS256", 4098},
      new Object[] {"RS384", 2048},
      new Object[] {"RS384", 3072},
      new Object[] {"RS512", 3072},
      new Object[] {"RS512", 4098},
    };
  }

  private static Object[] parametersTemplates() {
    return new Object[] {
      JwtEcdsaSignKeyManager.jwtES256Template(),
      JwtEcdsaSignKeyManager.jwtES384Template(),
      JwtEcdsaSignKeyManager.jwtES512Template(),
      JwtRsaSsaPkcs1SignKeyManager.jwtRsa2048AlgoRS256F4Template(),
      JwtRsaSsaPkcs1SignKeyManager.jwtRsa4096AlgoRS512F4Template(),
      JwtRsaSsaPkcs1SignKeyManager.jwtRsa3072AlgoRS384F4Template(),
      JwtRsaSsaPkcs1SignKeyManager.jwtRsa3072AlgoRS256F4Template(),
      JwtRsaSsaPssSignKeyManager.jwtRsa2048AlgoPS256F4Template(),
      JwtRsaSsaPssSignKeyManager.jwtRsa4096AlgoPS512F4Template(),
      JwtRsaSsaPssSignKeyManager.jwtRsa3072AlgoPS384F4Template(),
      JwtRsaSsaPssSignKeyManager.jwtRsa3072AlgoPS256F4Template(),
      JwtRsaSsaPssSignKeyManager.jwtRsa4096AlgoPS512F4Template(),
      JwtRsaSsaPssSignKeyManager.jwtRsa3072AlgoPS384F4Template(),
      JwtRsaSsaPssSignKeyManager.jwtRsa3072AlgoPS256F4Template()
    };
  }

  @Before
  public void setUp() throws GeneralSecurityException {
    JwtSignatureConfig.register();
  }

  private static final KeyPair generateRsaKeyPair(int keySize) throws GeneralSecurityException {
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
    keyGen.initialize(keySize);
    return keyGen.generateKeyPair();
  }

  private static final KeyPair generateEcdsaKeyPair(ECParameterSpec curve)
      throws GeneralSecurityException {
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
    keyGen.initialize(curve);
    return keyGen.generateKeyPair();
  }

  @Test
  public void test_wrapEmpty_throws() throws Exception {
    PrimitiveSet<JwtPublicKeySign> primitiveSet =
        PrimitiveSet.newPrimitiveSet(JwtPublicKeySign.class);

    try {
      signWrapper.wrap(primitiveSet);
      fail();
    } catch (GeneralSecurityException e) {
      // expected
    }
  }

  @Test
  @Parameters(method = "parametersCurvesAndAlgos")
  public void test_wrapNoPrimaryEcdsa_throws(ECParameterSpec curve, String algorithm)
      throws Exception {
    PrimitiveSet<JwtPublicKeySign> primitiveSet =
        PrimitiveSet.newPrimitiveSet(JwtPublicKeySign.class);

    KeyPair keyPair = generateEcdsaKeyPair(curve);
    ECPrivateKey privKey = (ECPrivateKey) keyPair.getPrivate();

    primitiveSet.addPrimitive(
        new JwtEcdsaSign(privKey, algorithm),
        Keyset.Key.newBuilder()
            .setKeyId(202020)
            .setStatus(KeyStatusType.ENABLED)
            .setOutputPrefixType(OutputPrefixType.RAW)
            .build());

    try {
      signWrapper.wrap(primitiveSet);
      fail();
    } catch (GeneralSecurityException e) {
      // expected
    }
  }

  @Test
  @Parameters(method = "parametersPssAlgosAndSizes")
  public void test_wrapNoPrimaryPss_throws(String algorithm, int keySize) throws Exception {
    PrimitiveSet<JwtPublicKeySign> primitiveSet =
        PrimitiveSet.newPrimitiveSet(JwtPublicKeySign.class);

    KeyPair keyPair = generateRsaKeyPair(keySize);
    RSAPrivateCrtKey privKey = (RSAPrivateCrtKey) keyPair.getPrivate();

    primitiveSet.addPrimitive(
        new JwtRsaSsaPssSign(privKey, algorithm),
        Keyset.Key.newBuilder()
            .setKeyId(202020)
            .setStatus(KeyStatusType.ENABLED)
            .setOutputPrefixType(OutputPrefixType.RAW)
            .build());

    try {
      signWrapper.wrap(primitiveSet);
      fail();
    } catch (GeneralSecurityException e) {
      // expected
    }
  }

  @Test
  @Parameters(method = "parametersPkcs1AlgosAndSizes")
  public void test_wrapNoPrimaryPkcs1_throws(String algorithm, int keySize) throws Exception {
    PrimitiveSet<JwtPublicKeySign> primitiveSet =
        PrimitiveSet.newPrimitiveSet(JwtPublicKeySign.class);

    KeyPair keyPair = generateRsaKeyPair(keySize);
    RSAPrivateCrtKey privKey = (RSAPrivateCrtKey) keyPair.getPrivate();

    primitiveSet.addPrimitive(
        new JwtRsaSsaPkcs1Sign(privKey, algorithm),
        Keyset.Key.newBuilder()
            .setKeyId(202020)
            .setStatus(KeyStatusType.ENABLED)
            .setOutputPrefixType(OutputPrefixType.RAW)
            .build());

    try {
      signWrapper.wrap(primitiveSet);
      fail();
    } catch (GeneralSecurityException e) {
      // expected
    }
  }

  @Test
  @Parameters(method = "parametersPkcs1AlgosAndSizes")
  public void test_wrapNoRawPkcs1_throws(String algorithm, int keySize) throws Exception {
    PrimitiveSet<JwtPublicKeySign> primitiveSet =
        PrimitiveSet.newPrimitiveSet(JwtPublicKeySign.class);

    KeyPair keyPair = generateRsaKeyPair(keySize);
    RSAPrivateCrtKey privKey = (RSAPrivateCrtKey) keyPair.getPrivate();

    primitiveSet.addPrimitive(
        new JwtRsaSsaPkcs1Sign(privKey, algorithm),
        Keyset.Key.newBuilder()
            .setKeyId(202020)
            .setStatus(KeyStatusType.ENABLED)
            .setOutputPrefixType(OutputPrefixType.TINK)
            .build());
    PrimitiveSet.Entry<JwtPublicKeySign> entry =
        primitiveSet.addPrimitive(
            new JwtRsaSsaPkcs1Sign(privKey, algorithm),
            Keyset.Key.newBuilder()
                .setKeyId(202021)
                .setStatus(KeyStatusType.ENABLED)
                .setOutputPrefixType(OutputPrefixType.RAW)
                .build());
    primitiveSet.setPrimary(entry);

    try {
      signWrapper.wrap(primitiveSet);
      fail();
    } catch (GeneralSecurityException e) {
      // expected
    }
  }

  @Test
  @Parameters(method = "parametersPssAlgosAndSizes")
  public void test_wrapNoRawPss_throws(String algorithm, int keySize) throws Exception {
    PrimitiveSet<JwtPublicKeySign> primitiveSet =
        PrimitiveSet.newPrimitiveSet(JwtPublicKeySign.class);

    KeyPair keyPair = generateRsaKeyPair(keySize);
    RSAPrivateCrtKey privKey = (RSAPrivateCrtKey) keyPair.getPrivate();

    primitiveSet.addPrimitive(
        new JwtRsaSsaPssSign(privKey, algorithm),
        Keyset.Key.newBuilder()
            .setKeyId(202020)
            .setStatus(KeyStatusType.ENABLED)
            .setOutputPrefixType(OutputPrefixType.TINK)
            .build());
    PrimitiveSet.Entry<JwtPublicKeySign> entry =
        primitiveSet.addPrimitive(
            new JwtRsaSsaPssSign(privKey, algorithm),
            Keyset.Key.newBuilder()
                .setKeyId(202021)
                .setStatus(KeyStatusType.ENABLED)
                .setOutputPrefixType(OutputPrefixType.RAW)
                .build());
    primitiveSet.setPrimary(entry);

    try {
      signWrapper.wrap(primitiveSet);
      fail();
    } catch (GeneralSecurityException e) {
      // expected
    }
  }

  @Test
  @Parameters(method = "parametersCurvesAndAlgos")
  public void test_wrapNoRawEcdsa_throws(ECParameterSpec curve, String algorithm) throws Exception {
    PrimitiveSet<JwtPublicKeySign> primitiveSet =
        PrimitiveSet.newPrimitiveSet(JwtPublicKeySign.class);

    KeyPair keyPair = generateEcdsaKeyPair(curve);
    ECPrivateKey privKey = (ECPrivateKey) keyPair.getPrivate();

    primitiveSet.addPrimitive(
        new JwtEcdsaSign(privKey, algorithm),
        Keyset.Key.newBuilder()
            .setKeyId(202020)
            .setStatus(KeyStatusType.ENABLED)
            .setOutputPrefixType(OutputPrefixType.TINK)
            .build());

    PrimitiveSet.Entry<JwtPublicKeySign> entry =
        primitiveSet.addPrimitive(
            new JwtEcdsaSign(privKey, algorithm),
            Keyset.Key.newBuilder()
                .setKeyId(202021)
                .setStatus(KeyStatusType.ENABLED)
                .setOutputPrefixType(OutputPrefixType.RAW)
                .build());
    primitiveSet.setPrimary(entry);

    try {
      signWrapper.wrap(primitiveSet);
      fail();
    } catch (GeneralSecurityException e) {
      // expected
    }
  }

  @Test
  @Parameters(method = "parametersPssAlgosAndSizes")
  public void test_wrapSinglePss_works(String algorithm, int keySize) throws Exception {
    PrimitiveSet<JwtPublicKeySign> primitivePrivSet =
        PrimitiveSet.newPrimitiveSet(JwtPublicKeySign.class);
    PrimitiveSet<JwtPublicKeyVerify> primitivePubSet =
        PrimitiveSet.newPrimitiveSet(JwtPublicKeyVerify.class);

    KeyPair keyPair = generateRsaKeyPair(keySize);
    RSAPrivateCrtKey privKey = (RSAPrivateCrtKey) keyPair.getPrivate();
    RSAPublicKey pubKey = (RSAPublicKey) keyPair.getPublic();

    PrimitiveSet.Entry<JwtPublicKeySign> entryPriv =
        primitivePrivSet.addPrimitive(
            new JwtRsaSsaPssSign(privKey, algorithm),
            Keyset.Key.newBuilder()
                .setKeyId(202020)
                .setStatus(KeyStatusType.ENABLED)
                .setOutputPrefixType(OutputPrefixType.RAW)
                .build());

    PrimitiveSet.Entry<JwtPublicKeyVerify> entryPub =
        primitivePubSet.addPrimitive(
            new JwtRsaSsaPssVerify(pubKey, algorithm),
            Keyset.Key.newBuilder()
                .setKeyId(202020)
                .setStatus(KeyStatusType.ENABLED)
                .setOutputPrefixType(OutputPrefixType.RAW)
                .build());

    primitivePrivSet.setPrimary(entryPriv);
    JwtPublicKeySign wrappedSign = signWrapper.wrap(primitivePrivSet);

    primitivePubSet.setPrimary(entryPub);
    JwtPublicKeyVerify wrappedVerify = verifyWrapper.wrap(primitivePubSet);

    RawJwt rawJwt = new RawJwt.Builder().setJwtId("blah").build();
    String compact = wrappedSign.sign(rawJwt);
    JwtValidator validator = new JwtValidator.Builder().build();
    VerifiedJwt token = wrappedVerify.verify(compact, validator);

    assertThat(token.getJwtId()).isEqualTo("blah");
  }

  @Test
  @Parameters(method = "parametersPkcs1AlgosAndSizes")
  public void test_wrapSinglePkcs1_works(String algorithm, int keySize) throws Exception {
    PrimitiveSet<JwtPublicKeySign> primitivePrivSet =
        PrimitiveSet.newPrimitiveSet(JwtPublicKeySign.class);
    PrimitiveSet<JwtPublicKeyVerify> primitivePubSet =
        PrimitiveSet.newPrimitiveSet(JwtPublicKeyVerify.class);

    KeyPair keyPair = generateRsaKeyPair(keySize);
    RSAPrivateCrtKey privKey = (RSAPrivateCrtKey) keyPair.getPrivate();
    RSAPublicKey pubKey = (RSAPublicKey) keyPair.getPublic();

    PrimitiveSet.Entry<JwtPublicKeySign> entryPriv =
        primitivePrivSet.addPrimitive(
            new JwtRsaSsaPkcs1Sign(privKey, algorithm),
            Keyset.Key.newBuilder()
                .setKeyId(202020)
                .setStatus(KeyStatusType.ENABLED)
                .setOutputPrefixType(OutputPrefixType.RAW)
                .build());

    PrimitiveSet.Entry<JwtPublicKeyVerify> entryPub =
        primitivePubSet.addPrimitive(
            new JwtRsaSsaPkcs1Verify(pubKey, algorithm),
            Keyset.Key.newBuilder()
                .setKeyId(202020)
                .setStatus(KeyStatusType.ENABLED)
                .setOutputPrefixType(OutputPrefixType.RAW)
                .build());

    primitivePrivSet.setPrimary(entryPriv);
    JwtPublicKeySign wrappedSign = signWrapper.wrap(primitivePrivSet);

    primitivePubSet.setPrimary(entryPub);
    JwtPublicKeyVerify wrappedVerify = verifyWrapper.wrap(primitivePubSet);

    RawJwt rawJwt = new RawJwt.Builder().setJwtId("blah").build();
    String compact = wrappedSign.sign(rawJwt);
    JwtValidator validator = new JwtValidator.Builder().build();
    VerifiedJwt token = wrappedVerify.verify(compact, validator);

    assertThat(token.getJwtId()).isEqualTo("blah");
  }

  @Test
  @Parameters(method = "parametersCurvesAndAlgos")
  public void test_wrapSingleEcdsa_works(ECParameterSpec curve, String algorithm) throws Exception {
    PrimitiveSet<JwtPublicKeySign> primitivePrivSet =
        PrimitiveSet.newPrimitiveSet(JwtPublicKeySign.class);
    PrimitiveSet<JwtPublicKeyVerify> primitivePubSet =
        PrimitiveSet.newPrimitiveSet(JwtPublicKeyVerify.class);

    KeyPair keyPair = generateEcdsaKeyPair(curve);
    ECPrivateKey privKey = (ECPrivateKey) keyPair.getPrivate();
    ECPublicKey pubKey = (ECPublicKey) keyPair.getPublic();

    PrimitiveSet.Entry<JwtPublicKeySign> entryPriv =
        primitivePrivSet.addPrimitive(
            new JwtEcdsaSign(privKey, algorithm),
            Keyset.Key.newBuilder()
                .setKeyId(202020)
                .setStatus(KeyStatusType.ENABLED)
                .setOutputPrefixType(OutputPrefixType.RAW)
                .build());

    PrimitiveSet.Entry<JwtPublicKeyVerify> entryPub =
        primitivePubSet.addPrimitive(
            new JwtEcdsaVerify(pubKey, algorithm),
            Keyset.Key.newBuilder()
                .setKeyId(202020)
                .setStatus(KeyStatusType.ENABLED)
                .setOutputPrefixType(OutputPrefixType.RAW)
                .build());

    primitivePrivSet.setPrimary(entryPriv);
    JwtPublicKeySign wrappedSign = signWrapper.wrap(primitivePrivSet);

    primitivePubSet.setPrimary(entryPub);
    JwtPublicKeyVerify wrappedVerify = verifyWrapper.wrap(primitivePubSet);

    RawJwt rawJwt = new RawJwt.Builder().setJwtId("blah").build();
    String compact = wrappedSign.sign(rawJwt);
    JwtValidator validator = new JwtValidator.Builder().build();
    VerifiedJwt token = wrappedVerify.verify(compact, validator);

    assertThat(token.getJwtId()).isEqualTo("blah");
  }

  @Test
  @Parameters(method = "parametersPkcs1AlgosAndSizes")
  public void test_wrapMultiplePkcs1_works(String algorithm, int keySize) throws Exception {
    PrimitiveSet<JwtPublicKeySign> primitivePrivSet =
        PrimitiveSet.newPrimitiveSet(JwtPublicKeySign.class);

    PrimitiveSet<JwtPublicKeyVerify> primitivePubSet =
        PrimitiveSet.newPrimitiveSet(JwtPublicKeyVerify.class);

    KeyPair keyPair = generateRsaKeyPair(keySize);
    RSAPrivateCrtKey privKey = (RSAPrivateCrtKey) keyPair.getPrivate();
    RSAPublicKey pubKey = (RSAPublicKey) keyPair.getPublic();

    KeyPair keyPair2 = generateRsaKeyPair(keySize);
    RSAPrivateCrtKey privKey2 = (RSAPrivateCrtKey) keyPair2.getPrivate();
    RSAPublicKey pubKey2 = (RSAPublicKey) keyPair2.getPublic();

    primitivePrivSet.addPrimitive(
        new JwtRsaSsaPkcs1Sign(privKey, algorithm),
        Keyset.Key.newBuilder()
            .setKeyId(202020)
            .setStatus(KeyStatusType.ENABLED)
            .setOutputPrefixType(OutputPrefixType.RAW)
            .build());

    PrimitiveSet.Entry<JwtPublicKeySign> entry2 =
        primitivePrivSet.addPrimitive(
            new JwtRsaSsaPkcs1Sign(privKey2, algorithm),
            Keyset.Key.newBuilder()
                .setKeyId(202020)
                .setStatus(KeyStatusType.ENABLED)
                .setOutputPrefixType(OutputPrefixType.RAW)
                .build());
    JwtRsaSsaPkcs1Verify verifier1 = new JwtRsaSsaPkcs1Verify(pubKey, algorithm);

    JwtRsaSsaPkcs1Verify verifier2 = new JwtRsaSsaPkcs1Verify(pubKey2, algorithm);
    PrimitiveSet.Entry<JwtPublicKeyVerify> entryPub =
        primitivePubSet.addPrimitive(
            verifier2,
            Keyset.Key.newBuilder()
                .setKeyId(202020)
                .setStatus(KeyStatusType.ENABLED)
                .setOutputPrefixType(OutputPrefixType.RAW)
                .build());

    primitivePrivSet.setPrimary(entry2);
    JwtPublicKeySign wrappedSign = signWrapper.wrap(primitivePrivSet);

    primitivePubSet.setPrimary(entryPub);
    JwtPublicKeyVerify wrappedVerify = verifyWrapper.wrap(primitivePubSet);

    RawJwt rawJwt = new RawJwt.Builder().setJwtId("blah").build();
    String compact = wrappedSign.sign(rawJwt);
    JwtValidator validator = new JwtValidator.Builder().build();
    VerifiedJwt token = wrappedVerify.verify(compact, validator);
    VerifiedJwt token2 = verifier2.verify(compact, validator);

    assertThrows(GeneralSecurityException.class, () -> verifier1.verify(compact, validator));
    assertThat(token.getJwtId()).isEqualTo("blah");
    assertThat(token2.getJwtId()).isEqualTo("blah");
  }

  @Test
  @Parameters(method = "parametersPssAlgosAndSizes")
  public void test_wrapMultiplePss_works(String algorithm, int keySize) throws Exception {
    PrimitiveSet<JwtPublicKeySign> primitivePrivSet =
        PrimitiveSet.newPrimitiveSet(JwtPublicKeySign.class);

    PrimitiveSet<JwtPublicKeyVerify> primitivePubSet =
        PrimitiveSet.newPrimitiveSet(JwtPublicKeyVerify.class);

    KeyPair keyPair = generateRsaKeyPair(keySize);
    RSAPrivateCrtKey privKey = (RSAPrivateCrtKey) keyPair.getPrivate();
    RSAPublicKey pubKey = (RSAPublicKey) keyPair.getPublic();

    KeyPair keyPair2 = generateRsaKeyPair(keySize);
    RSAPrivateCrtKey privKey2 = (RSAPrivateCrtKey) keyPair2.getPrivate();
    RSAPublicKey pubKey2 = (RSAPublicKey) keyPair2.getPublic();

    primitivePrivSet.addPrimitive(
        new JwtRsaSsaPssSign(privKey, algorithm),
        Keyset.Key.newBuilder()
            .setKeyId(202020)
            .setStatus(KeyStatusType.ENABLED)
            .setOutputPrefixType(OutputPrefixType.RAW)
            .build());

    PrimitiveSet.Entry<JwtPublicKeySign> entry2 =
        primitivePrivSet.addPrimitive(
            new JwtRsaSsaPssSign(privKey2, algorithm),
            Keyset.Key.newBuilder()
                .setKeyId(202020)
                .setStatus(KeyStatusType.ENABLED)
                .setOutputPrefixType(OutputPrefixType.RAW)
                .build());
    JwtRsaSsaPssVerify verifier1 = new JwtRsaSsaPssVerify(pubKey, algorithm);

    JwtRsaSsaPssVerify verifier2 = new JwtRsaSsaPssVerify(pubKey2, algorithm);
    PrimitiveSet.Entry<JwtPublicKeyVerify> entryPub =
        primitivePubSet.addPrimitive(
            verifier2,
            Keyset.Key.newBuilder()
                .setKeyId(202020)
                .setStatus(KeyStatusType.ENABLED)
                .setOutputPrefixType(OutputPrefixType.RAW)
                .build());

    primitivePrivSet.setPrimary(entry2);
    JwtPublicKeySign wrappedSign = signWrapper.wrap(primitivePrivSet);

    primitivePubSet.setPrimary(entryPub);
    JwtPublicKeyVerify wrappedVerify = verifyWrapper.wrap(primitivePubSet);

    RawJwt rawJwt = new RawJwt.Builder().setJwtId("blah").build();
    String compact = wrappedSign.sign(rawJwt);
    JwtValidator validator = new JwtValidator.Builder().build();
    VerifiedJwt token = wrappedVerify.verify(compact, validator);
    VerifiedJwt token2 = verifier2.verify(compact, validator);

    assertThrows(GeneralSecurityException.class, () -> verifier1.verify(compact, validator));
    assertThat(token.getJwtId()).isEqualTo("blah");
    assertThat(token2.getJwtId()).isEqualTo("blah");
  }

  @Test
  @Parameters(method = "parametersCurvesAndAlgos")
  public void test_wrapMultipleEcdsa_works(ECParameterSpec curve, String algorithm)
      throws Exception {
    PrimitiveSet<JwtPublicKeySign> primitivePrivSet =
        PrimitiveSet.newPrimitiveSet(JwtPublicKeySign.class);

    PrimitiveSet<JwtPublicKeyVerify> primitivePubSet =
        PrimitiveSet.newPrimitiveSet(JwtPublicKeyVerify.class);

    KeyPair keyPair = generateEcdsaKeyPair(curve);
    ECPrivateKey privKey = (ECPrivateKey) keyPair.getPrivate();
    ECPublicKey pubKey = (ECPublicKey) keyPair.getPublic();

    KeyPair keyPair2 = generateEcdsaKeyPair(curve);
    ECPrivateKey privKey2 = (ECPrivateKey) keyPair2.getPrivate();
    ECPublicKey pubKey2 = (ECPublicKey) keyPair2.getPublic();

    primitivePrivSet.addPrimitive(
        new JwtEcdsaSign(privKey, algorithm),
        Keyset.Key.newBuilder()
            .setKeyId(202020)
            .setStatus(KeyStatusType.ENABLED)
            .setOutputPrefixType(OutputPrefixType.RAW)
            .build());

    PrimitiveSet.Entry<JwtPublicKeySign> entry2 =
        primitivePrivSet.addPrimitive(
            new JwtEcdsaSign(privKey2, algorithm),
            Keyset.Key.newBuilder()
                .setKeyId(202020)
                .setStatus(KeyStatusType.ENABLED)
                .setOutputPrefixType(OutputPrefixType.RAW)
                .build());
    JwtEcdsaVerify verifier1 = new JwtEcdsaVerify(pubKey, algorithm);

    JwtEcdsaVerify verifier2 = new JwtEcdsaVerify(pubKey2, algorithm);
    PrimitiveSet.Entry<JwtPublicKeyVerify> entryPub =
        primitivePubSet.addPrimitive(
            verifier2,
            Keyset.Key.newBuilder()
                .setKeyId(202020)
                .setStatus(KeyStatusType.ENABLED)
                .setOutputPrefixType(OutputPrefixType.RAW)
                .build());

    primitivePrivSet.setPrimary(entry2);
    JwtPublicKeySign wrappedSign = signWrapper.wrap(primitivePrivSet);

    primitivePubSet.setPrimary(entryPub);
    JwtPublicKeyVerify wrappedVerify = verifyWrapper.wrap(primitivePubSet);

    RawJwt rawJwt = new RawJwt.Builder().setJwtId("blah").build();
    String compact = wrappedSign.sign(rawJwt);
    JwtValidator validator = new JwtValidator.Builder().build();
    VerifiedJwt token = wrappedVerify.verify(compact, validator);
    VerifiedJwt token2 = verifier2.verify(compact, validator);

    assertThrows(GeneralSecurityException.class, () -> verifier1.verify(compact, validator));
    assertThat(token.getJwtId()).isEqualTo("blah");
    assertThat(token2.getJwtId()).isEqualTo("blah");
  }

  @Test
  @Parameters(method = "parametersTemplates")
  public void wrongKey_throwsInvalidSignatureException(KeyTemplate template) throws Exception {
    KeysetHandle keysetHandle = KeysetHandle.generateNew(template);
    JwtPublicKeySign jwtSign = keysetHandle.getPrimitive(JwtPublicKeySign.class);
    RawJwt rawJwt = new RawJwt.Builder().build();
    String compact = jwtSign.sign(rawJwt);
    JwtValidator validator = new JwtValidator.Builder().build();

    KeysetHandle wrongKeysetHandle = KeysetHandle.generateNew(template);
    KeysetHandle wrongPublicKeysetHandle = wrongKeysetHandle.getPublicKeysetHandle();

    JwtPublicKeyVerify wrongJwtVerify =
        wrongPublicKeysetHandle.getPrimitive(JwtPublicKeyVerify.class);
    assertThrows(GeneralSecurityException.class, () -> wrongJwtVerify.verify(compact, validator));
  }

  @Test
  @Parameters(method = "parametersTemplates")
  public void wrongIssuer_throwsInvalidException(KeyTemplate template) throws Exception {
    KeysetHandle keysetHandle = KeysetHandle.generateNew(template);
    JwtPublicKeySign jwtSigner = keysetHandle.getPrimitive(JwtPublicKeySign.class);
    KeysetHandle publicHandle = keysetHandle.getPublicKeysetHandle();
    JwtPublicKeyVerify jwtVerifier = publicHandle.getPrimitive(JwtPublicKeyVerify.class);
    RawJwt rawJwt = new RawJwt.Builder().setIssuer("Justus").build();
    String compact = jwtSigner.sign(rawJwt);
    JwtValidator validator = new JwtValidator.Builder().setIssuer("Peter").build();
    assertThrows(JwtInvalidException.class, () -> jwtVerifier.verify(compact, validator));
  }

  @Test
  @Parameters(method = "parametersTemplates")
  public void expiredCompact_throwsExpiredException(KeyTemplate template) throws Exception {
    KeysetHandle keysetHandle = KeysetHandle.generateNew(template);
    JwtPublicKeySign jwtSigner = keysetHandle.getPrimitive(JwtPublicKeySign.class);
    KeysetHandle publicHandle = keysetHandle.getPublicKeysetHandle();
    JwtPublicKeyVerify jwtVerifier = publicHandle.getPrimitive(JwtPublicKeyVerify.class);

    Instant now = Clock.systemUTC().instant().truncatedTo(ChronoUnit.SECONDS);
    RawJwt rawJwt =
        new RawJwt.Builder()
            .setExpiration(now.minusSeconds(100)) // exipired 100 seconds ago
            .setIssuedAt(now.minusSeconds(200))
            .build();
    String compact = jwtSigner.sign(rawJwt);
    JwtValidator validator = new JwtValidator.Builder().build();
    assertThrows(JwtInvalidException.class, () -> jwtVerifier.verify(compact, validator));
  }

  @Test
  @Parameters(method = "parametersTemplates")
  public void notYetValidCompact_throwsNotBeforeException(KeyTemplate template) throws Exception {
    KeysetHandle keysetHandle = KeysetHandle.generateNew(template);
    JwtPublicKeySign jwtSigner = keysetHandle.getPrimitive(JwtPublicKeySign.class);
    KeysetHandle publicHandle = keysetHandle.getPublicKeysetHandle();
    JwtPublicKeyVerify jwtVerifier = publicHandle.getPrimitive(JwtPublicKeyVerify.class);

    Instant now = Clock.systemUTC().instant().truncatedTo(ChronoUnit.SECONDS);
    RawJwt rawJwt =
        new RawJwt.Builder()
            .setNotBefore(now.plusSeconds(3600)) // is valid in 1 hour, but not before
            .setIssuedAt(now)
            .build();
    String compact = jwtSigner.sign(rawJwt);
    JwtValidator validator = new JwtValidator.Builder().build();
    assertThrows(JwtInvalidException.class, () -> jwtVerifier.verify(compact, validator));
  }
}
