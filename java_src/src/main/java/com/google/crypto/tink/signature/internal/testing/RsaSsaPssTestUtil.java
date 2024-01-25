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
import com.google.crypto.tink.signature.RsaSsaPssParameters;
import com.google.crypto.tink.signature.RsaSsaPssPrivateKey;
import com.google.crypto.tink.signature.RsaSsaPssPublicKey;
import com.google.crypto.tink.subtle.Base64;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.util.SecretBigInteger;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import javax.annotation.Nullable;

/** Test utilities for RsaSsaPss */
@AccessesPartialKey
public final class RsaSsaPssTestUtil {
  private static RsaSsaPssPrivateKey privateKeyFor2048BitParameters(
      RsaSsaPssParameters parameters, @Nullable Integer idRequirement)
      throws GeneralSecurityException {
    // Some parameters are from https://www.rfc-editor.org/rfc/rfc7517#appendix-C,
    // but the actual signatures were computed with this implementation.
    BigInteger publicModulus =
        new BigInteger(
            1,
            Base64.urlSafeDecode(
                "t6Q8PWSi1dkJj9hTP8hNYFlvadM7DflW9mWepOJhJ66w7nyoK1gPNqFMSQRy"
                    + "O125Gp-TEkodhWr0iujjHVx7BcV0llS4w5ACGgPrcAd6ZcSR0-Iqom-QFcNP"
                    + "8Sjg086MwoqQU_LYywlAGZ21WSdS_PERyGFiNnj3QQlO8Yns5jCtLCRwLHL0"
                    + "Pb1fEv45AuRIuUfVcPySBWYnDyGxvjYGDSM-AqWS9zIQ2ZilgT-GqUmipg0X"
                    + "OC0Cc20rgLe2ymLHjpHciCKVAbY5-L32-lSeZO-Os6U15_aXrk9Gw8cPUaX1"
                    + "_I8sLGuSiVdt3C_Fn2PZ3Z8i744FPFGGcG1qs2Wz-Q"));

    BigInteger primeP =
        new BigInteger(
            1,
            Base64.urlSafeDecode(
                "2rnSOV4hKSN8sS4CgcQHFbs08XboFDqKum3sc4h3GRxrTmQdl1ZK9uw-PIHf"
                    + "QP0FkxXVrx-WE-ZEbrqivH_2iCLUS7wAl6XvARt1KkIaUxPPSYB9yk31s0Q8"
                    + "UK96E3_OrADAYtAJs-M3JxCLfNgqh56HDnETTQhH3rCT5T3yJws"));
    BigInteger primeQ =
        new BigInteger(
            1,
            Base64.urlSafeDecode(
                "1u_RiFDP7LBYh3N4GXLT9OpSKYP0uQZyiaZwBtOCBNJgQxaj10RWjsZu0c6I"
                    + "edis4S7B_coSKB0Kj9PaPaBzg-IySRvvcQuPamQu66riMhjVtG6TlV8CLCYK"
                    + "rYl52ziqK0E_ym2QnkwsUX7eYTB7LbAHRK9GqocDE5B0f808I4s"));
    BigInteger exponentD =
        new BigInteger(
            1,
            Base64.urlSafeDecode(
                "GRtbIQmhOZtyszfgKdg4u_N-R_mZGU_9k7JQ_jn1DnfTuMdSNprTeaSTyWfS"
                    + "NkuaAwnOEbIQVy1IQbWVV25NY3ybc_IhUJtfri7bAXYEReWaCl3hdlPKXy9U"
                    + "vqPYGR0kIXTQRqns-dVJ7jahlI7LyckrpTmrM8dWBo4_PMaenNnPiQgO0xnu"
                    + "ToxutRZJfJvG4Ox4ka3GORQd9CsCZ2vsUDmsXOfUENOyMqADC6p1M3h33tsu"
                    + "rY15k9qMSpG9OX_IJAXmxzAh_tWiZOwk2K4yxH9tS3Lq1yX8C1EWmeRDkK2a"
                    + "hecG85-oLKQt5VEpWHKmjOi_gJSdSgqcN96X52esAQ"));
    BigInteger primeExponentP =
        new BigInteger(
            1,
            Base64.urlSafeDecode(
                "KkMTWqBUefVwZ2_Dbj1pPQqyHSHjj90L5x_MOzqYAJMcLMZtbUtwKqvVDq3"
                    + "tbEo3ZIcohbDtt6SbfmWzggabpQxNxuBpoOOf_a_HgMXK_lhqigI4y_kqS1w"
                    + "Y52IwjUn5rgRrJ-yYo1h41KR-vz2pYhEAeYrhttWtxVqLCRViD6c"));
    BigInteger primeExponentQ =
        new BigInteger(
            1,
            Base64.urlSafeDecode(
                "AvfS0-gRxvn0bwJoMSnFxYcK1WnuEjQFluMGfwGitQBWtfZ1Er7t1xDkbN9"
                    + "GQTB9yqpDoYaN06H7CFtrkxhJIBQaj6nkF5KKS3TQtQ5qCzkOkmxIe3KRbBy"
                    + "mXxkb5qwUpX5ELD5xFc6FeiafWYY63TmmEAu_lRFCOJ3xDea-ots"));
    BigInteger qInverse =
        new BigInteger(
            1,
            Base64.urlSafeDecode(
                "lSQi-w9CpyUReMErP1RsBLk7wNtOvs5EQpPqmuMvqW57NBUczScEoPwmUqq"
                    + "abu9V0-Py4dQ57_bapoKRu1R90bvuFnU63SHWEFglZQvJDMeAvmj4sm-Fp0o"
                    + "Yu_neotgQ0hzbI5gry7ajdYy9-2lNx_76aBZoOUu9HCJ-UsfSOI8"));

    RsaSsaPssPublicKey publicKey =
        RsaSsaPssPublicKey.builder()
            .setParameters(parameters)
            .setModulus(publicModulus)
            .setIdRequirement(idRequirement)
            .build();
    return RsaSsaPssPrivateKey.builder()
        .setPublicKey(publicKey)
        .setPrimes(
            SecretBigInteger.fromBigInteger(primeP, InsecureSecretKeyAccess.get()),
            SecretBigInteger.fromBigInteger(primeQ, InsecureSecretKeyAccess.get()))
        .setPrivateExponent(
            SecretBigInteger.fromBigInteger(exponentD, InsecureSecretKeyAccess.get()))
        .setPrimeExponents(
            SecretBigInteger.fromBigInteger(primeExponentP, InsecureSecretKeyAccess.get()),
            SecretBigInteger.fromBigInteger(primeExponentQ, InsecureSecretKeyAccess.get()))
        .setCrtCoefficient(SecretBigInteger.fromBigInteger(qInverse, InsecureSecretKeyAccess.get()))
        .build();
  }

  private static SignatureTestVector createTestVector0() throws GeneralSecurityException {
    RsaSsaPssParameters parameters =
        RsaSsaPssParameters.builder()
            .setModulusSizeBits(2048)
            .setSigHashType(RsaSsaPssParameters.HashType.SHA256)
            .setMgf1HashType(RsaSsaPssParameters.HashType.SHA256)
            .setVariant(RsaSsaPssParameters.Variant.NO_PREFIX)
            .setSaltLengthBytes(32)
            .build();
    return new SignatureTestVector(
        privateKeyFor2048BitParameters(parameters, /* idRequirement= */ null),
        Hex.decode(
            "97db7e8f38015cb1d14530c0bf3a28dfdd61e7570f3fea2d2933ba0afbbe6358f7d0c39e9647fd27c9b441"
                + "557dc3e1ce34f8664bfdf93a7b1af78650eae4ed61f16c8583058296019fe968e92bcf35f38cb85a"
                + "32c2107a76790a95a715440da281d026172b8b6e043af417852988441dac5ea888c849668bdcbb58"
                + "f5c34ebe9ab5d16f7fa6cff32e9ed6a65c58708d887af791a33f34f7fc2da8885a9c867d347c6f92"
                + "996dcb24f99701d2b955bb66f38c057f4acd51ff02da59c3bc129593820552ca07825a7e9920c266"
                + "8c8eb99f2a541d9ef34f34054fda0d8a792822cc00f3f274fa0fcbf3c6a32f9fb85cba8dc713941f"
                + "92a7a4f082693a2f79ff8198d6"),
        Hex.decode("aa"));
  }

  // SigHash & Mfg1Hash: SHA512
  private static SignatureTestVector createTestVector1() throws GeneralSecurityException {
    RsaSsaPssParameters parameters =
        RsaSsaPssParameters.builder()
            .setModulusSizeBits(2048)
            .setSigHashType(RsaSsaPssParameters.HashType.SHA512)
            .setMgf1HashType(RsaSsaPssParameters.HashType.SHA512)
            .setVariant(RsaSsaPssParameters.Variant.NO_PREFIX)
            .setSaltLengthBytes(32)
            .build();
    return new SignatureTestVector(
        privateKeyFor2048BitParameters(parameters, /* idRequirement= */ null),
        Hex.decode(
            "b21a035305dbe9119803932330dbfcc4ab11bf15f1b89b974e53e5e48d54433a230ec189da5f0c77e53fb0"
                + "eb320fd36a9e7209ffc78759cc409c15d67b858782afa5f9c67d3880275d67cd98c40064adf08d9a"
                + "58f0badb5c47b88a06ed81a23ffb131380c2f3bbc16a9290d13d31df54e2061b2f0acb3629a3693f"
                + "03b3f2004b451de3e1ae2861654d145a5723f102f65533598aa5bc8e40b67190386a45fe99bf17c4"
                + "610b2edf2538878989cacffd57b4c27c82ab72d95f380e50f0282423d759a6d06241cd88a817e3c9"
                + "67ff0e2dd1cbbacc9402ffee0acf41bbec54ea2bbe01edadf0382c8ab2a897580c1cdf4e412032a0"
                + "83d1e5d47a625a38aac8c552e1"),
        Hex.decode("aa"));
  }

  // Variant: TINK
  private static SignatureTestVector createTestVector2() throws GeneralSecurityException {
    RsaSsaPssParameters parameters =
        RsaSsaPssParameters.builder()
            .setModulusSizeBits(2048)
            .setSigHashType(RsaSsaPssParameters.HashType.SHA256)
            .setMgf1HashType(RsaSsaPssParameters.HashType.SHA256)
            .setVariant(RsaSsaPssParameters.Variant.TINK)
            .setSaltLengthBytes(32)
            .build();
    return new SignatureTestVector(
        privateKeyFor2048BitParameters(parameters, 0x99887766),
        Hex.decode(
            "0199887766"
                + "97db7e8f38015cb1d14530c0bf3a28dfdd61e7570f3fea2d2933ba0afbbe6358f7d0c39e9647fd27"
                + "c9b441557dc3e1ce34f8664bfdf93a7b1af78650eae4ed61f16c8583058296019fe968e92bcf35f3"
                + "8cb85a32c2107a76790a95a715440da281d026172b8b6e043af417852988441dac5ea888c849668b"
                + "dcbb58f5c34ebe9ab5d16f7fa6cff32e9ed6a65c58708d887af791a33f34f7fc2da8885a9c867d34"
                + "7c6f92996dcb24f99701d2b955bb66f38c057f4acd51ff02da59c3bc129593820552ca07825a7e99"
                + "20c2668c8eb99f2a541d9ef34f34054fda0d8a792822cc00f3f274fa0fcbf3c6a32f9fb85cba8dc7"
                + "13941f92a7a4f082693a2f79ff8198d6"),
        Hex.decode("aa"));
  }

  // Variant: CRUNCHY
  private static SignatureTestVector createTestVector3() throws GeneralSecurityException {
    RsaSsaPssParameters parameters =
        RsaSsaPssParameters.builder()
            .setModulusSizeBits(2048)
            .setSigHashType(RsaSsaPssParameters.HashType.SHA256)
            .setMgf1HashType(RsaSsaPssParameters.HashType.SHA256)
            .setVariant(RsaSsaPssParameters.Variant.CRUNCHY)
            .setSaltLengthBytes(32)
            .build();
    return new SignatureTestVector(
        privateKeyFor2048BitParameters(parameters, 0x99887766),
        Hex.decode(
            "0099887766"
                + "97db7e8f38015cb1d14530c0bf3a28dfdd61e7570f3fea2d2933ba0afbbe6358f7d0c39e9647fd27"
                + "c9b441557dc3e1ce34f8664bfdf93a7b1af78650eae4ed61f16c8583058296019fe968e92bcf35f3"
                + "8cb85a32c2107a76790a95a715440da281d026172b8b6e043af417852988441dac5ea888c849668b"
                + "dcbb58f5c34ebe9ab5d16f7fa6cff32e9ed6a65c58708d887af791a33f34f7fc2da8885a9c867d34"
                + "7c6f92996dcb24f99701d2b955bb66f38c057f4acd51ff02da59c3bc129593820552ca07825a7e99"
                + "20c2668c8eb99f2a541d9ef34f34054fda0d8a792822cc00f3f274fa0fcbf3c6a32f9fb85cba8dc7"
                + "13941f92a7a4f082693a2f79ff8198d6"),
        Hex.decode("aa"));
  }

  // Variant: LEGACY
  private static SignatureTestVector createTestVector4() throws GeneralSecurityException {
    RsaSsaPssParameters parameters =
        RsaSsaPssParameters.builder()
            .setModulusSizeBits(2048)
            .setSigHashType(RsaSsaPssParameters.HashType.SHA256)
            .setMgf1HashType(RsaSsaPssParameters.HashType.SHA256)
            .setVariant(RsaSsaPssParameters.Variant.LEGACY)
            .setSaltLengthBytes(32)
            .build();
    return new SignatureTestVector(
        privateKeyFor2048BitParameters(parameters, 0x99887766),
        Hex.decode(
            "0099887766"
                + "433065815d23c7beff4780228b0e6212d7cedd6998c5528bd5b0a3ce90066a4a1f76c703745c23b4"
                + "f7d92a5c84871dc9e6b2800d2bebd3d651afa86b1eb68924bacabc0699358417319f5f9f7b326e63"
                + "6457c6098676f61c549b25c40975ee5cefa4c3c2b7d5d81efa0a78e4c777908762a0348022d425aa"
                + "fcdc4f6ada902d359758ad75ae8988eb522ea11771c9d84fc9ffe6f3b317872335b1d4af5f60e40e"
                + "1a0d2588cb6640383b5b193f094754c21250485eb9430b056bab0d781ba261bd6cf80ad520402b83"
                + "bc30a81d9ce38b7de9844d7d1310696de099dbf2b642cfca8edb6b098c71d50710668870f3e47b11"
                + "5ecf4a0933573c92027d737647daa9f8"),
        Hex.decode("aa"));
  }

  // SaltLengthBytes: 64
  private static SignatureTestVector createTestVector5() throws GeneralSecurityException {
    RsaSsaPssParameters parameters =
        RsaSsaPssParameters.builder()
            .setModulusSizeBits(2048)
            .setSigHashType(RsaSsaPssParameters.HashType.SHA256)
            .setMgf1HashType(RsaSsaPssParameters.HashType.SHA256)
            .setVariant(RsaSsaPssParameters.Variant.NO_PREFIX)
            .setSaltLengthBytes(64)
            .build();
    return new SignatureTestVector(
        privateKeyFor2048BitParameters(parameters, /* idRequirement= */ null),
        Hex.decode(
            "aa5310c40c83878e0116ccc09efda3be6a88c667c797e61b6831e109fd6b5fbed9df08cf05711d79cb3841"
                + "64fc5ddfb0de10a5110053c2b073449603bb11994fc0847d929806d5034e24db0662df5c0963fbac"
                + "1d214842c4de1d7f4bfb741d8a2866e24819e8073042d17bccef92bbcdc6b34ca052486d60d12e9d"
                + "992cebaaca5df2d7ea31c08af4d35338cdaa460a0ee568ff2bdaab1d72d6a8360713d98a0923ae92"
                + "9cff9950fd48bf0fa05e4324f4f9561defbb8e2c4854122394dd55bda740d57064956255e36c6c1c"
                + "c1970947d630121df570ba577957dd23116e9bf4c2c826ec4b52223735dd0c355165485ff6652656"
                + "aa471a190c7f40e26c85440fc8"),
        Hex.decode("aa"));
  }

  // KeySize: 4096 bits
  private static SignatureTestVector createTestVector6() throws GeneralSecurityException {
    RsaSsaPssParameters parameters =
        RsaSsaPssParameters.builder()
            .setModulusSizeBits(4096)
            .setSigHashType(RsaSsaPssParameters.HashType.SHA256)
            .setMgf1HashType(RsaSsaPssParameters.HashType.SHA256)
            .setVariant(RsaSsaPssParameters.Variant.NO_PREFIX)
            .setSaltLengthBytes(32)
            .build();
    BigInteger privateExponent =
        new BigInteger(
            1,
            Base64.urlSafeDecode(
                "QfFSeY4zl5LKG1MstcHg6IfBjyQ36inrbjSBMmk7_nPSnWo61B2LqOHr90EWgBlj03Q7IDrDymiLb-l9Gv"
                    + "bMsRGmM4eDCKlPf5_6vtpTfN6dcrR2-KD9shaQgMVlHdgaX9a4RelBmq3dqaKVob0-sfsEBkyrbC"
                    + "apIENUp8ECrERzJUP_vTtUKlYR3WnWRXlWmo-bYN5FPZrh2I0ZWLSF8EK9__ssfBxVO9DZgZwFd-"
                    + "k7vSkgbisjUN6LBiVDEEF2kY1AeBIzMtvrDlkskEXPUim2qnTS6f15h7ErZfvwJYqTPR3dQL-yqz"
                    + "RdYTBSNiGDrKdhCINL5FLI8NYQqifPF4hjPPlUVBCBoblOeSUnokh7l5VyTYShfS-Y24HjjUiZWk"
                    + "XnNWsS0rubRYV69rq79GC45EwAvwQRPhGjYEQpS3BAzfdodjSVe_1_scCVVi7GpmhrEqz-ZJE3BY"
                    + "i39ioGRddlGIMmMt_ddYpHNgt16qfLBGjJU2rveyxXm2zPZz-W-lJC8AjH8RqzFYikec2LNZ49xM"
                    + "KiBAijpghSCoVCO_kTaesc6crJ125AL5T5df_C65JeXoCQsbbvQRdqQs4TG9uObkY8OWZ1VHjhUF"
                    + "b1frplDQvc4bUqYFgQxGhrDFAbwKBECyUwqh0hJnDtQpFFcvhJj6AILVoLlVqNeWIK3iE"));
    BigInteger publicModulus =
        new BigInteger(
            1,
            Base64.urlSafeDecode(
                "AK9mcI3PaEhMPR2ICXxCsK0lek917W01OVK24Q6_eMKVJkzVKhf2muYn2B1Pkx_yvdWr7g0B1tjNSN66-A"
                    + "PH7osa9F1x6WnzY16d2WY3xvidHxHMFol1sPa-xGKu94uFBp4rHqrj7nYBJX4QmHzLG95QANhJPz"
                    + "C4P9M-lrVSyCVlHr2732NZpjoFN8dZtvNvNI_ndUb4fTgozmxbaRKGKawTjocP1DAtOzwwuOKPZM"
                    + "WwI3nFEEDJqkhFh2uiINPWYtcs-onHXeKLpCJUwCXC4bEmgPErChOO3kvlZF6K2o8uoNBPkhnBog"
                    + "q7tl8gxjnJWK5AdN2vZflmIwKuQaWB-12d341-5omqm-V9roqf7WpObLpkX1VeLeK9V96dnUl864"
                    + "bap8RXvJlrQ-OMCBNax3YmtqMHWjafXe1tNavvEA8zi8dOchwyyUQ5xaPM_taf29AJA6F8xbeHFR"
                    + "sAMX8piBOZYNZUm7SHu8tJOrAXmyDldCIeob2O4MRzMwfRgvQS_NAQNwPMuOBrpRr3b4slV6CfXs"
                    + "k4cWTb3gs7ZXeSQFbJVmhaMDSjOFUzXxs75J4Ud639loa8jF0j7f5kInzR1t-UYj7YajigirKPaX"
                    + "nI1OXxn0ZkBIRln0pVIbQFX5YJ96K9-YOpJnBNgYY_PNcvfl5SD87vYNOQxsbeIQIE-EkF"));
    BigInteger primeP =
        new BigInteger(
            1,
            Base64.urlSafeDecode(
                "AOQA7Ky1XEGqZcc7uSXwFbKjSNCmVBhCGqsDRdKJ1ErSmW98gnJ7pBIHTmiyFdJqU20SzY-YB05Xj3bfSY"
                    + "ptJRPLO2cGiwrwjRB_EsG8OqexX_5le9_8x-8i6MhY3xGX5LABYs8dB0aLl3ysOtRgIvCeyeoJ0I"
                    + "7nRYjwDlexxjl9z7OI28cW7Tdvljbk-LAgBmygsMluP2-n7T58Dl-SD-8BT5eiGFDFu76h_vmyTX"
                    + "B1_zToAqBK2C5oM7OF_7Z7zuLjx7vz40xH6KD7Rkkvcwm95wfhYEZtHYFwqUhajE1vD5nCcGcCNh"
                    + "quTLzPlW5RN2Asxm-_Dk-p7pIkH9aAP0k"));
    BigInteger primeQ =
        new BigInteger(
            1,
            Base64.urlSafeDecode(
                "AMTv-c5IRTRvbx7Vyf06df2Rm2AwdaRlwy1QG3YAdojQ_PhICNH0-mTHqYaeNZRja6KniFKqaYimgdccW2"
                    + "UhGGKZXQhHhyucZ-AE0NtPLFkd7RhegcrH5sbHOcDtWCSGwcne9Wzs54VyhIhGmOS5HYuLUD-sB0"
                    + "NgMzm8vNsnF_qIt458x6L4GE97HnRnLdSJBFaNkEdLJGXN1fbtJIGgdKN1aOc5KafTi-q2DAHEe3"
                    + "SmTzFPWD6NJ-jo0aJE9fXRQ06BUwUJtZXwaC4FCpcZKne2PSglc8AlqQOulcFLrsJ8fnG_vc7trS"
                    + "_pw9zCxaaJQduYPyTbM9_szBj206lJb90"));
    BigInteger primeExponentP =
        new BigInteger(
            1,
            Base64.urlSafeDecode(
                "WQVTYwtcffb9zhAvdfSLRDgkkfKfGumUZ_jbJhzSWnRnm_PNKs3DfZaEsrP1eTYyZH_W6p29HIVrako7-G"
                    + "Qs-dF72_neB-Nr8Gjs9d98N0U16anN9-JGXcQPh0nLrp7TlzSzU5JN6OlPuEm2nnz6p2AYDdzPJT"
                    + "x_FbxEnVC3yHKqybpBtTXqYJ6c08oKnxmh6H_FBqCY_AtgwejF4-Kvfe3RGa8cN008xG2TlAJd4e"
                    + "7wOcPsYpFWXqgop4tGEAW-_S9aKLRMptfcqB3zj1eLXt5aeeUxJc4smwFV1v4jkYgvWyVjpZRjc3"
                    + "9iTsXt3iivqklRIQhDmi8LCtw34hQooQ"));
    BigInteger primeExponentQ =
        new BigInteger(
            1,
            Base64.urlSafeDecode(
                "AI3R7wghPU0Mbm47MPGeFvga0lSLsTxJWCuag5wPq0zNi07UuR1RmLvYmPlrl1Qb4JhKoz48oDEbD2e0cR"
                    + "C7q47duIRM1keOo7NMZId6VYp7pZEmBbvdBxDgyXNouE_dh1JzsDPXysZr-IsWo-YadO9XzNt9a-"
                    + "GWNm1-wFXlqjvuFpmSvEVc-kzKcd0LrJJgdXJLEbp1n2l8uHfQwLhkr3pDA993Z8sG6byFitH_B5"
                    + "Sya1csN3UcO8BbYRPFK4bxQtIXCY0YN98ZODzjvoOfSNjasOHnTprxw-v13rxLXzeJZZlOpkaNHG"
                    + "njovuoe6N5NqcH1XkaLho0sanMnhJL4zU"));
    BigInteger crtCoefficient =
        new BigInteger(
            1,
            Base64.urlSafeDecode(
                "AL6gykI07B_tLc5MEUbwAZec8frBkcIvwdlnbchmov9q5sBnI7xJt07BJlyrm8p_XWuOblmx6Qg4ccKwE1"
                    + "jt3Cd36J7X92D9IJwfagytmeT4wmruM7Qbuzg7iGeX4RJ4CLkvsJZRSh8Fvum-qMwEynypVJMB5-"
                    + "Uw8Y_6Cd_nMZeSK7pJs8ewrS7LDY7ODnrzxkJ1xRCXpVbvsB0mKcOmhM9fD6Q1qkjwmBn4MYBE2D"
                    + "1im_S2Ybt2AiSjAxMX6M8u8N8hXcEu0ozeTfsZy1HOF9HuTRdOdEh4P-ZvzQqawSLF5HTk82_-F-"
                    + "yiTPhtlcqCNFbCs0pKGeZIFZQ9ZfK5kn8"));
    RsaSsaPssPublicKey publicKey =
        RsaSsaPssPublicKey.builder().setParameters(parameters).setModulus(publicModulus).build();
    RsaSsaPssPrivateKey privateKey =
        RsaSsaPssPrivateKey.builder()
            .setPublicKey(publicKey)
            .setPrimes(
                SecretBigInteger.fromBigInteger(primeP, InsecureSecretKeyAccess.get()),
                SecretBigInteger.fromBigInteger(primeQ, InsecureSecretKeyAccess.get()))
            .setPrivateExponent(
                SecretBigInteger.fromBigInteger(privateExponent, InsecureSecretKeyAccess.get()))
            .setPrimeExponents(
                SecretBigInteger.fromBigInteger(primeExponentP, InsecureSecretKeyAccess.get()),
                SecretBigInteger.fromBigInteger(primeExponentQ, InsecureSecretKeyAccess.get()))
            .setCrtCoefficient(
                SecretBigInteger.fromBigInteger(crtCoefficient, InsecureSecretKeyAccess.get()))
            .build();

    return new SignatureTestVector(
        privateKey,
        Hex.decode(
            "20c933ec5b1c7862d3695e4e98ce4494fb9225ffcca5cb6ff165790c856a7600092b8dc57c1e551fc8a85b"
                + "6e0731f4e6b148c9b2b1ab72f8ea528591fa2cfc35a1d893d00aabff2d66471bcfa84cafa033d33c"
                + "a9964c13ee316ddfdde2d1766272d60440f5df0eba22f419f2b95c2decf3621f0c3cb311b7f72bf2"
                + "ca740414b31f74d3dd042abd005a1adc9aa4e57b65ef813476d7294aa516f04f96211dcc74497fd7"
                + "f876997595ef1d3e9be241c0455acda0d004ecfbd66bba5b98fcec6d8bba4ede1d88ab585e422142"
                + "167ac6fc096ddf389598f35a7b361f1946212e71b0d6f5ae5ae594bd4bc4ed52a8aa21607d845f2f"
                + "9b921cc05edd12a8ecdb40d1265c4e038855dbcf895c9ce0012f62194eafa3aec3ae38fcf9922e80"
                + "b3f123bfa6f5eea4d90036057eeabf3219fefd6bb9205489a9fb55e1ff280ab946350ca3dd7cd328"
                + "c033a4e5756bffaa83f94767d02dcd2ba0c78af4e4dc51fae1125f683278c659fb9e2b269131af86"
                + "410599d798e0d626477fb94af9be8e7c95f12467434b12fb415cea98c4eb05d879ef1e7eebf79268"
                + "68f21d9e51c184bdc679c8aceda400bb4edc29c029b4b939b2ac43d712ef4b68a058f5f45ac70022"
                + "abc5fec9389333a8b67a54b4a994f3ca7fdf14c73b5b130220fcc2607b27bdfa2b37e115bc8ccfe2"
                + "489f51642f8556b0240ad86f7620d3e7664f76ac671da08e92b76f512b"),
        Hex.decode("aa"));
  }

  public static SignatureTestVector[] createRsaPssTestVectors() {
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
            });
  }

  private RsaSsaPssTestUtil() {}
}
