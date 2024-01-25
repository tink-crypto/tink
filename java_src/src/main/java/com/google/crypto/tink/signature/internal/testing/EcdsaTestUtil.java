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

package com.google.crypto.tink.signature.internal.testing;

import static com.google.crypto.tink.internal.TinkBugException.exceptionIsBug;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.signature.EcdsaParameters;
import com.google.crypto.tink.signature.EcdsaPrivateKey;
import com.google.crypto.tink.signature.EcdsaPublicKey;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.util.SecretBigInteger;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.spec.ECPoint;

/** Test utilities for ECDSA */
@AccessesPartialKey
public final class EcdsaTestUtil {
  // Point from https://www.ietf.org/rfc/rfc6979.txt, A.2.5
  private static ECPoint getP256Point() {
    return new ECPoint(
        new BigInteger("60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6", 16),
        new BigInteger("7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299", 16));
  }

  private static SecretBigInteger getPrivateP256Value() {
    return SecretBigInteger.fromBigInteger(
        new BigInteger("C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721", 16),
        InsecureSecretKeyAccess.get());
  }

  private static ECPoint getP384Point() {
    return new ECPoint(
        new BigInteger(
            "009d92e0330dfc60ba8b2be32e10f7d2f8457678a112cafd4544b29b7e6addf0249968f54c"
                + "732aa49bc4a38f467edb8424",
            16),
        new BigInteger(
            "0081a3a9c9e878b86755f018a8ec3c5e80921910af919b95f18976e35acc04efa2962e277a"
                + "0b2c990ae92b62d6c75180ba",
            16));
  }

  private static SecretBigInteger getPrivateP384Value() {
    return SecretBigInteger.fromBigInteger(
        new BigInteger(
            "670dc60402d8a4fe52f4e552d2b71f0f81bcf195d8a71a6c7d84efb4f0e4b4a5d0f60a27c9"
                + "4caac46bdeeb79897a3ed9",
            16),
        InsecureSecretKeyAccess.get());
  }

  private static SignatureTestVector createTestVector0() throws GeneralSecurityException {
    EcdsaParameters parameters =
        EcdsaParameters.builder()
            .setSignatureEncoding(EcdsaParameters.SignatureEncoding.IEEE_P1363)
            .setCurveType(EcdsaParameters.CurveType.NIST_P256)
            .setHashType(EcdsaParameters.HashType.SHA256)
            .setVariant(EcdsaParameters.Variant.NO_PREFIX)
            .build();
    EcdsaPublicKey publicKey =
        EcdsaPublicKey.builder().setParameters(parameters).setPublicPoint(getP256Point()).build();
    EcdsaPrivateKey privateKey =
        EcdsaPrivateKey.builder()
            .setPublicKey(publicKey)
            .setPrivateValue(getPrivateP256Value())
            .build();

    return new SignatureTestVector(
        privateKey,
        Hex.decode(
            "70cbee11e536e9c83d2a2abc6be049117fdab0c420db8191e36f8ce2855262bb5d0b69eefc4dea7b086aa6"
                + "2186e9a7c8600e7b0f1252f704271d5189e7a5cf03"),
        Hex.decode(""));
  }

  // Signature encoding: DER
  private static SignatureTestVector createTestVector1() throws GeneralSecurityException {
    EcdsaParameters parameters =
        EcdsaParameters.builder()
            .setSignatureEncoding(EcdsaParameters.SignatureEncoding.DER)
            .setCurveType(EcdsaParameters.CurveType.NIST_P256)
            .setHashType(EcdsaParameters.HashType.SHA256)
            .setVariant(EcdsaParameters.Variant.NO_PREFIX)
            .build();
    EcdsaPublicKey publicKey =
        EcdsaPublicKey.builder().setParameters(parameters).setPublicPoint(getP256Point()).build();
    EcdsaPrivateKey privateKey =
        EcdsaPrivateKey.builder()
            .setPublicKey(publicKey)
            .setPrivateValue(getPrivateP256Value())
            .build();

    return new SignatureTestVector(
        privateKey,
        Hex.decode(
            "3046022100baca7d618e43d44f2754a5368f60b4a41925e2c04d27a672b276ae1f4b3c63a2022100d404a3"
                + "015cb229f7cb036c2b5f77cc546065eed4b75837cec2883d1e35d5eb9f"),
        Hex.decode(""));
  }

  // Variant: TINK
  private static SignatureTestVector createTestVector2() throws GeneralSecurityException {
    EcdsaParameters parameters =
        EcdsaParameters.builder()
            .setSignatureEncoding(EcdsaParameters.SignatureEncoding.IEEE_P1363)
            .setCurveType(EcdsaParameters.CurveType.NIST_P256)
            .setHashType(EcdsaParameters.HashType.SHA256)
            .setVariant(EcdsaParameters.Variant.TINK)
            .build();
    EcdsaPublicKey publicKey =
        EcdsaPublicKey.builder()
            .setParameters(parameters)
            .setIdRequirement(0x99887766)
            .setPublicPoint(getP256Point())
            .build();
    EcdsaPrivateKey privateKey =
        EcdsaPrivateKey.builder()
            .setPublicKey(publicKey)
            .setPrivateValue(getPrivateP256Value())
            .build();

    return new SignatureTestVector(
        privateKey,
        Hex.decode(
            "0199887766"
                + "9b04881165ae47c99c637d306c537bdc97a336ed6f358c7fac1124b3f7166f7d5da6a7b20c61090200276f"
                + "a25ff25e6e39cf56fb5499973b66f25bc1921a1fda"),
        Hex.decode(""));
  }

  // Variant: CRUNCHY
  private static SignatureTestVector createTestVector3() throws GeneralSecurityException {
    EcdsaParameters parameters =
        EcdsaParameters.builder()
            .setSignatureEncoding(EcdsaParameters.SignatureEncoding.IEEE_P1363)
            .setCurveType(EcdsaParameters.CurveType.NIST_P256)
            .setHashType(EcdsaParameters.HashType.SHA256)
            .setVariant(EcdsaParameters.Variant.CRUNCHY)
            .build();
    EcdsaPublicKey publicKey =
        EcdsaPublicKey.builder()
            .setParameters(parameters)
            .setIdRequirement(0x99887766)
            .setPublicPoint(getP256Point())
            .build();
    EcdsaPrivateKey privateKey =
        EcdsaPrivateKey.builder()
            .setPublicKey(publicKey)
            .setPrivateValue(getPrivateP256Value())
            .build();

    return new SignatureTestVector(
        privateKey,
        Hex.decode(
            "0099887766"
                + "9b04881165ae47c99c637d306c537bdc97a336ed6f358c7fac1124b3f7166f7d5da6a7b20c61090200276f"
                + "a25ff25e6e39cf56fb5499973b66f25bc1921a1fda"),
        Hex.decode(""));
  }

  // Variant: LEGACY
  private static SignatureTestVector createTestVector4() throws GeneralSecurityException {
    EcdsaParameters parameters =
        EcdsaParameters.builder()
            .setSignatureEncoding(EcdsaParameters.SignatureEncoding.IEEE_P1363)
            .setCurveType(EcdsaParameters.CurveType.NIST_P256)
            .setHashType(EcdsaParameters.HashType.SHA256)
            .setVariant(EcdsaParameters.Variant.LEGACY)
            .build();
    EcdsaPublicKey publicKey =
        EcdsaPublicKey.builder()
            .setParameters(parameters)
            .setIdRequirement(0x99887766)
            .setPublicPoint(getP256Point())
            .build();
    EcdsaPrivateKey privateKey =
        EcdsaPrivateKey.builder()
            .setPublicKey(publicKey)
            .setPrivateValue(getPrivateP256Value())
            .build();

    return new SignatureTestVector(
        privateKey,
        Hex.decode(
            "0099887766"
                + "515b67e48efb8ebc12e0ce691cf210b18c1e96409667aaedd8d744c64aff843a4e09ebfb9b6c40a6"
                + "540dd0d835693ca08da8c1d8e434770511459088243b0bbb"),
        Hex.decode(""));
  }

  // Non-empty message
  private static SignatureTestVector createTestVector5() throws GeneralSecurityException {
    EcdsaParameters parameters =
        EcdsaParameters.builder()
            .setSignatureEncoding(EcdsaParameters.SignatureEncoding.IEEE_P1363)
            .setCurveType(EcdsaParameters.CurveType.NIST_P256)
            .setHashType(EcdsaParameters.HashType.SHA256)
            .setVariant(EcdsaParameters.Variant.NO_PREFIX)
            .build();
    EcdsaPublicKey publicKey =
        EcdsaPublicKey.builder().setParameters(parameters).setPublicPoint(getP256Point()).build();
    EcdsaPrivateKey privateKey =
        EcdsaPrivateKey.builder()
            .setPublicKey(publicKey)
            .setPrivateValue(getPrivateP256Value())
            .build();

    return new SignatureTestVector(
        privateKey,
        Hex.decode(
            "bfec68e554a26e161b657efb368a6cd0ec3499c92f2b6240e1b92fa724366a79ca37137274c9125e34c286"
                + "439c848ce3594a3f9450f4108a2fc287a120dfab4f"),
        Hex.decode("001122"));
  }

  // NIST_P384
  private static SignatureTestVector createTestVector6() throws GeneralSecurityException {
    EcdsaParameters parameters =
        EcdsaParameters.builder()
            .setSignatureEncoding(EcdsaParameters.SignatureEncoding.IEEE_P1363)
            .setCurveType(EcdsaParameters.CurveType.NIST_P384)
            .setHashType(EcdsaParameters.HashType.SHA384)
            .setVariant(EcdsaParameters.Variant.NO_PREFIX)
            .build();
    EcdsaPublicKey publicKey =
        EcdsaPublicKey.builder().setParameters(parameters).setPublicPoint(getP384Point()).build();
    EcdsaPrivateKey privateKey =
        EcdsaPrivateKey.builder()
            .setPublicKey(publicKey)
            .setPrivateValue(getPrivateP384Value())
            .build();

    return new SignatureTestVector(
        privateKey,
        Hex.decode(
            "eb19dc251dcbb0aac7634c646b27ccc59a21d6231e08d2b6031ec729ecb0e9927b70bfa66d458b5e1b7186"
                + "355644fa9150602bade9f0c358b9d28263cb427f58bf7d9b892ac75f43ab048360b34ee81653f85e"
                + "c2f10e6e4f0f0e0cafbe91f883"),
        Hex.decode(""));
  }

  // NIST_P384, SHA512
  private static SignatureTestVector createTestVector7() throws GeneralSecurityException {
    EcdsaParameters parameters =
        EcdsaParameters.builder()
            .setSignatureEncoding(EcdsaParameters.SignatureEncoding.IEEE_P1363)
            .setCurveType(EcdsaParameters.CurveType.NIST_P384)
            .setHashType(EcdsaParameters.HashType.SHA512)
            .setVariant(EcdsaParameters.Variant.NO_PREFIX)
            .build();
    EcdsaPublicKey publicKey =
        EcdsaPublicKey.builder().setParameters(parameters).setPublicPoint(getP384Point()).build();
    EcdsaPrivateKey privateKey =
        EcdsaPrivateKey.builder()
            .setPublicKey(publicKey)
            .setPrivateValue(getPrivateP384Value())
            .build();

    return new SignatureTestVector(
        privateKey,
        Hex.decode(
            "3db99cec1a865909886f8863ccfa3147f21ccad262a41abc8d964fafa55141a9d89efa6bf0acb4e5ec357c"
                + "6056542e7e016d4a653fde985aad594763900f3f9c4494f45f7a4450422640f57b0ad467950f78dd"
                + "b56641676cb91d392410ed606d"),
        Hex.decode(""));
  }

  // NIST_P521
  private static SignatureTestVector createTestVector8() throws GeneralSecurityException {
    EcdsaParameters parameters =
        EcdsaParameters.builder()
            .setSignatureEncoding(EcdsaParameters.SignatureEncoding.IEEE_P1363)
            .setCurveType(EcdsaParameters.CurveType.NIST_P521)
            .setHashType(EcdsaParameters.HashType.SHA512)
            .setVariant(EcdsaParameters.Variant.NO_PREFIX)
            .build();
    EcdsaPublicKey publicKey =
        EcdsaPublicKey.builder()
            .setParameters(parameters)
            .setPublicPoint(
                new ECPoint(
                    new BigInteger(
                        "1894550D0785932E00EAA23B694F213F8C3121F86DC97A04E5A7167DB4E5BCD3"
                            + "71123D46E45DB6B5D5370A7F20FB633155D38FFA16D2BD761DCAC474B9A2F502"
                            + "3A4",
                        16),
                    new BigInteger(
                        "0493101C962CD4D2FDDF782285E64584139C2F91B47F87FF82354D6630F746A2"
                            + "8A0DB25741B5B34A828008B22ACC23F924FAAFBD4D33F81EA66956DFEAA2BFDF"
                            + "CF5",
                        16)))
            .build();
    EcdsaPrivateKey privateKey =
        EcdsaPrivateKey.builder()
            .setPublicKey(publicKey)
            .setPrivateValue(
                SecretBigInteger.fromBigInteger(
                    new BigInteger(
                        "0FAD06DAA62BA3B25D2FB40133DA757205DE67F5BB0018FEE8C86E1B68C7E75C"
                            + "AA896EB32F1F47C70855836A6D16FCC1466F6D8FBEC67DB89EC0C08B0E996B83"
                            + "538",
                        16),
                    InsecureSecretKeyAccess.get()))
            .build();

    return new SignatureTestVector(
        privateKey,
        Hex.decode(
            "00eaf6672f0696a46046d3b1572814b697c7904fe265fece75e33b90833d08af6513adfb6cbf0a49714426"
                + "33c981d11cd068fcf9431cbe49448b4240a067d860f7fb0168a8d7bf1602050b2255e844aea1df8d"
                + "8ad770053d2c915cca2af6e175c2fb0944f6a9e3262fb9b99910e7fbd6ef4aca887b901ec78678d3"
                + "ec48529c7f06e8c815"),
        Hex.decode(""));
  }

  public static SignatureTestVector[] createEcdsaTestVectors() {
    return exceptionIsBug(
        () ->
            new SignatureTestVector[] {
              createTestVector0(),
              createTestVector1(),
              createTestVector2(),
              createTestVector3(),
              createTestVector4(),
              createTestVector5(),
              createTestVector6(),
              createTestVector7(),
              createTestVector8(),
            });
  }

  private EcdsaTestUtil() {}
}
