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

package com.google.crypto.tink.signature;

import static com.google.common.truth.Truth.assertThat;
import static java.nio.charset.StandardCharsets.UTF_8;

import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.PublicKeySign;
import com.google.crypto.tink.PublicKeyVerify;
import com.google.crypto.tink.util.SecretBigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class KeyConversionTest {

  @BeforeClass
  public static void setUp() throws Exception {
    SignatureConfig.register();
  }

  @Test
  public void signAndVerifyWithEcdsaUsingJavaECKeys() throws Exception {
    // Generate a EC key pair
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
    keyGen.initialize(EcdsaParameters.CurveType.NIST_P384.toParameterSpec());
    KeyPair keyPair = keyGen.generateKeyPair();
    PrivateKey privateKey = keyPair.getPrivate();
    PublicKey publicKey = keyPair.getPublic();

    // Convert publicKey into a Tink EcdsaPublicKey.
    ECPublicKey ecPublicKey = (ECPublicKey) publicKey;
    EcdsaPublicKey ecdsaPublicKey =
        EcdsaPublicKey.builder()
            .setParameters(
                EcdsaParameters.builder()
                    .setSignatureEncoding(EcdsaParameters.SignatureEncoding.IEEE_P1363)
                    .setCurveType(EcdsaParameters.CurveType.NIST_P384)
                    .setHashType(EcdsaParameters.HashType.SHA384)
                    .setVariant(EcdsaParameters.Variant.NO_PREFIX)
                    .build())
            .setPublicPoint(ecPublicKey.getW())
            .build();

    // Convert privateKey and publicKey into a Tink EcdsaPrivateKey.
    ECPrivateKey ecPrivateKey = (ECPrivateKey) privateKey;
    EcdsaPrivateKey ecdsaPrivateKey =
        EcdsaPrivateKey.builder()
            .setPublicKey(
                EcdsaPublicKey.builder()
                    .setParameters(
                        EcdsaParameters.builder()
                            .setSignatureEncoding(EcdsaParameters.SignatureEncoding.IEEE_P1363)
                            .setCurveType(EcdsaParameters.CurveType.NIST_P384)
                            .setHashType(EcdsaParameters.HashType.SHA384)
                            .setVariant(EcdsaParameters.Variant.NO_PREFIX)
                            .build())
                    .setPublicPoint(ecPublicKey.getW())
                    .build())
            .setPrivateValue(
                SecretBigInteger.fromBigInteger(ecPrivateKey.getS(), InsecureSecretKeyAccess.get()))
            .build();

    // Generate a PublicKeySign primitive from ecdsaPrivateKey and sign a message.
    KeysetHandle privateHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(ecdsaPrivateKey).withRandomId().makePrimary())
            .build();
    PublicKeySign signer = privateHandle.getPrimitive(PublicKeySign.class);
    byte[] data = "data".getBytes(UTF_8);
    byte[] sig = signer.sign(data);

    // Generate a PublicKeyVerify primitive from ecdsaPublicKey, and verify the signature.
    KeysetHandle publicHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(ecdsaPublicKey).withRandomId().makePrimary())
            .build();
    PublicKeyVerify verifier = publicHandle.getPrimitive(PublicKeyVerify.class);
    verifier.verify(sig, data);
  }

  /**
   * This test show how Tink can be used with Java RSA keys, by importing them as RSA SSA PKCS1
   * keys.
   */
  @Test
  public void signAndVerifyUsingJavaRSAKeys() throws Exception {
    // Generate a RSA key pair
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
    keyGen.initialize(/* keysize= */ 2048);
    KeyPair keyPair = keyGen.generateKeyPair();
    PrivateKey privateKey = keyPair.getPrivate();
    PublicKey publicKey = keyPair.getPublic();

    // Convert publicKey into a Tink RsaSsaPkcs1PublicKey.
    RSAPublicKey rsaPublicKey = (RSAPublicKey) publicKey;
    RsaSsaPkcs1PublicKey rsaSsaPkcs1PublicKey =
        RsaSsaPkcs1PublicKey.builder()
            .setParameters(
                RsaSsaPkcs1Parameters.builder()
                    .setModulusSizeBits(rsaPublicKey.getModulus().bitLength())
                    .setPublicExponent(rsaPublicKey.getPublicExponent())
                    .setHashType(RsaSsaPkcs1Parameters.HashType.SHA256)
                    .setVariant(RsaSsaPkcs1Parameters.Variant.NO_PREFIX)
                    .build())
            .setModulus(rsaPublicKey.getModulus())
            .build();

    // Convert privateKey and publicKey into a Tink RsaSsaPkcs1PrivateKey.
    RSAPrivateCrtKey rsaPrivateKey = (RSAPrivateCrtKey) privateKey;
    RsaSsaPkcs1PrivateKey rsaSsaPkcs1PrivateKey =
        RsaSsaPkcs1PrivateKey.builder()
            .setPublicKey(rsaSsaPkcs1PublicKey)
            .setPrimes(
                SecretBigInteger.fromBigInteger(
                    rsaPrivateKey.getPrimeP(), InsecureSecretKeyAccess.get()),
                SecretBigInteger.fromBigInteger(
                    rsaPrivateKey.getPrimeQ(), InsecureSecretKeyAccess.get()))
            .setPrivateExponent(
                SecretBigInteger.fromBigInteger(
                    rsaPrivateKey.getPrivateExponent(), InsecureSecretKeyAccess.get()))
            .setPrimeExponents(
                SecretBigInteger.fromBigInteger(
                    rsaPrivateKey.getPrimeExponentP(), InsecureSecretKeyAccess.get()),
                SecretBigInteger.fromBigInteger(
                    rsaPrivateKey.getPrimeExponentQ(), InsecureSecretKeyAccess.get()))
            .setCrtCoefficient(
                SecretBigInteger.fromBigInteger(
                    rsaPrivateKey.getCrtCoefficient(), InsecureSecretKeyAccess.get()))
            .build();

    // Generate a PublicKeySign primitive from rsaSsaPkcs1PrivateKey and sign a message.
    KeysetHandle privateHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(rsaSsaPkcs1PrivateKey).withRandomId().makePrimary())
            .build();
    PublicKeySign signer = privateHandle.getPrimitive(PublicKeySign.class);
    byte[] data = "data".getBytes(UTF_8);
    byte[] sig = signer.sign(data);

    // Generate a PublicKeyVerify primitive from rsaSsaPkcs1PublicKey, and verify the signature.
    KeysetHandle publicHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(rsaSsaPkcs1PublicKey).withRandomId().makePrimary())
            .build();
    PublicKeyVerify verifier = publicHandle.getPrimitive(PublicKeyVerify.class);
    verifier.verify(sig, data);

    // Verify using java.security.Signature.
    Signature signatureVerify = Signature.getInstance("SHA256withRSA");
    signatureVerify.initVerify(publicKey);
    signatureVerify.update(data);
    assertThat(signatureVerify.verify(sig)).isTrue();
  }
}
