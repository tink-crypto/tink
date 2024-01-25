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
import com.google.crypto.tink.signature.RsaSsaPkcs1Parameters;
import com.google.crypto.tink.signature.RsaSsaPkcs1PrivateKey;
import com.google.crypto.tink.signature.RsaSsaPkcs1PublicKey;
import com.google.crypto.tink.subtle.Base64;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.util.SecretBigInteger;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import javax.annotation.Nullable;

/** Test utilities for RsaSsaPkcs1 */
@AccessesPartialKey
public final class RsaSsaPkcs1TestUtil {
  private static RsaSsaPkcs1PrivateKey privateKeyFor2048BitParameters(
      RsaSsaPkcs1Parameters parameters, @Nullable Integer idRequirement)
      throws GeneralSecurityException {
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

    RsaSsaPkcs1PublicKey publicKey =
        RsaSsaPkcs1PublicKey.builder()
            .setParameters(parameters)
            .setModulus(publicModulus)
            .setIdRequirement(idRequirement)
            .build();
    return RsaSsaPkcs1PrivateKey.builder()
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

  public static SignatureTestVector createTestVector0() throws GeneralSecurityException {
    RsaSsaPkcs1Parameters parameters =
        RsaSsaPkcs1Parameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(RsaSsaPkcs1Parameters.F4)
            .setHashType(RsaSsaPkcs1Parameters.HashType.SHA256)
            .setVariant(RsaSsaPkcs1Parameters.Variant.NO_PREFIX)
            .build();
    RsaSsaPkcs1PrivateKey privateKey = privateKeyFor2048BitParameters(parameters, null);
    return new SignatureTestVector(
        privateKey,
        Hex.decode(
            "3d10ce911833c1fe3f3356580017d159e1557e019096499950f62c3768c716bca418828dc140e930ecceff"
                + "ebc532db66c77b433e51cef6dfbac86cb3aff6f5fc2a488faf35199b2e12c9fe2de7be3eea63bdc9"
                + "60e6694e4474c29e5610f5f7fa30ac23b015041353658c74998c3f620728b5859bad9c63d07be0b2"
                + "d3bbbea8b9121f47385e4cad92b31c0ef656eee782339d14fd6350bb3756663c03cb261f7ece6e03"
                + "355c7a4ecfe812c965f68890b2571916de0e2cd40814f9db9571065b5340ef7aa66d55a78cd62f4a"
                + "1bd496623184a3d29dd886c1d1331754915bcbb243e5677ea7bb21a18d1ee22b6ba92c15a23ed6ae"
                + "de20abc29b290cc04fa0846027"),
        Hex.decode("aa"));
  }

  // SHA512
  public static SignatureTestVector createTestVector1() throws GeneralSecurityException {
    RsaSsaPkcs1Parameters parameters =
        RsaSsaPkcs1Parameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(RsaSsaPkcs1Parameters.F4)
            .setHashType(RsaSsaPkcs1Parameters.HashType.SHA512)
            .setVariant(RsaSsaPkcs1Parameters.Variant.NO_PREFIX)
            .build();
    RsaSsaPkcs1PrivateKey privateKey = privateKeyFor2048BitParameters(parameters, null);
    return new SignatureTestVector(
        privateKey,
        Hex.decode(
            "67cbf2475fff2908ba2fbde91e5ac21901427cf3328b17a41a1ba41f955d64b6358c78417ca19d1bd83f36"
                + "0fe28e48c7e4fd3946349e19812d9fa41b546c6751fd49b4ad986c9f38c3af9993a8466b91839415"
                + "e6e334f6306984957784854bde60c3926cc1037f764d6182ea44d7398fbaeefcb8b3c84ba8277003"
                + "20d00ee28816ecb7ed90debf46183abcc55950ff9f9b935df5ffaebb0f0b12a9244ac4fc05012f99"
                + "d5df4c2b4a1a6cafab54f30ed9122531f4322ff11f8921c8b716827d5dd278c0dea49ebb67b188b8"
                + "259ed820f1e750e45fd7767b9acdf30b47275739036a15aa11dfe030595e49d6c71ea8cb6a016e41"
                + "67f3a4168eb4326d12ffed608c"),
        Hex.decode("aa"));
  }

  // TINK
  public static SignatureTestVector createTestVector2() throws GeneralSecurityException {
    RsaSsaPkcs1Parameters parameters =
        RsaSsaPkcs1Parameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(RsaSsaPkcs1Parameters.F4)
            .setHashType(RsaSsaPkcs1Parameters.HashType.SHA256)
            .setVariant(RsaSsaPkcs1Parameters.Variant.TINK)
            .build();
    RsaSsaPkcs1PrivateKey privateKey = privateKeyFor2048BitParameters(parameters, 0x99887766);
    return new SignatureTestVector(
        privateKey,
        Hex.decode(
            "01998877663d10ce911833c1fe3f3356580017d159e1557e019096499950f62c3768c716bca418828dc140"
                + "e930ecceffebc532db66c77b433e51cef6dfbac86cb3aff6f5fc2a488faf35199b2e12c9fe2de7be"
                + "3eea63bdc960e6694e4474c29e5610f5f7fa30ac23b015041353658c74998c3f620728b5859bad9c"
                + "63d07be0b2d3bbbea8b9121f47385e4cad92b31c0ef656eee782339d14fd6350bb3756663c03cb26"
                + "1f7ece6e03355c7a4ecfe812c965f68890b2571916de0e2cd40814f9db9571065b5340ef7aa66d55"
                + "a78cd62f4a1bd496623184a3d29dd886c1d1331754915bcbb243e5677ea7bb21a18d1ee22b6ba92c"
                + "15a23ed6aede20abc29b290cc04fa0846027"),
        Hex.decode("aa"));
  }

  // CRUNCHY
  public static SignatureTestVector createTestVector3() throws GeneralSecurityException {
    RsaSsaPkcs1Parameters parameters =
        RsaSsaPkcs1Parameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(RsaSsaPkcs1Parameters.F4)
            .setHashType(RsaSsaPkcs1Parameters.HashType.SHA256)
            .setVariant(RsaSsaPkcs1Parameters.Variant.CRUNCHY)
            .build();
    RsaSsaPkcs1PrivateKey privateKey = privateKeyFor2048BitParameters(parameters, 0x99887766);
    return new SignatureTestVector(
        privateKey,
        Hex.decode(
            "00998877663d10ce911833c1fe3f3356580017d159e1557e019096499950f62c3768c716bca418828dc140"
                + "e930ecceffebc532db66c77b433e51cef6dfbac86cb3aff6f5fc2a488faf35199b2e12c9fe2de7be"
                + "3eea63bdc960e6694e4474c29e5610f5f7fa30ac23b015041353658c74998c3f620728b5859bad9c"
                + "63d07be0b2d3bbbea8b9121f47385e4cad92b31c0ef656eee782339d14fd6350bb3756663c03cb26"
                + "1f7ece6e03355c7a4ecfe812c965f68890b2571916de0e2cd40814f9db9571065b5340ef7aa66d55"
                + "a78cd62f4a1bd496623184a3d29dd886c1d1331754915bcbb243e5677ea7bb21a18d1ee22b6ba92c"
                + "15a23ed6aede20abc29b290cc04fa0846027"),
        Hex.decode("aa"));
  }

  public static SignatureTestVector createTestVector4() throws GeneralSecurityException {
    RsaSsaPkcs1Parameters parameters =
        RsaSsaPkcs1Parameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(RsaSsaPkcs1Parameters.F4)
            .setHashType(RsaSsaPkcs1Parameters.HashType.SHA256)
            .setVariant(RsaSsaPkcs1Parameters.Variant.LEGACY)
            .build();
    RsaSsaPkcs1PrivateKey privateKey = privateKeyFor2048BitParameters(parameters, 0x99887766);
    return new SignatureTestVector(
        privateKey,
        Hex.decode(
            "00998877668aece22c45c0db3db64e00416ed906b45e9c8ffedc1715cb3ea6cd9855a16f1c25375dbdd902"
                + "8c79ad5ee192f1fa60d54efbe3d753e1c604ee7104398e2bae28d1690d8984155b0de78ab52d90d3"
                + "b90509a1b798e79aff83b12413fa09bed089e29e7107ca00b33be0797d5d2ab3033e04a689b63c52"
                + "f3595245ce6639af9c0f0d3c3dbe00f076f6dd0fd72d26579f1cffdb3218039de1b3de52b5626d2c"
                + "3f840386904009be88b896132580716563edffa6ba15b29cf2fa1503236a5bec3f4beb5f4cc96267"
                + "7b4c1760d0c99dadf7704586d67fe95ccb312fd82e5c965041caf12afce18641e54a812aa36faf14"
                + "e2250a06b78ac111b1a2c8913f13e2a3d341"),
        Hex.decode("aa"));
  }

  // 4096 bit modulus size
  public static SignatureTestVector createTestVector5() throws GeneralSecurityException {
    RsaSsaPkcs1Parameters parameters =
        RsaSsaPkcs1Parameters.builder()
            .setModulusSizeBits(4096)
            .setPublicExponent(RsaSsaPkcs1Parameters.F4)
            .setHashType(RsaSsaPkcs1Parameters.HashType.SHA256)
            .setVariant(RsaSsaPkcs1Parameters.Variant.NO_PREFIX)
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
    RsaSsaPkcs1PublicKey publicKey =
        RsaSsaPkcs1PublicKey.builder().setParameters(parameters).setModulus(publicModulus).build();
    RsaSsaPkcs1PrivateKey privateKey =
        RsaSsaPkcs1PrivateKey.builder()
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
            "122a08c6e8b9bf4cb437a00e55cf6ac96e216c4580af87e40be6227504e163c0c516b747d38a81f087f387"
                + "8242008e4d0ef400d02f5bdc6629bb2f323241fcbbaa84aa173324359bdf7e35becd68b3977367ae"
                + "ecf8cfb4a9497f883547c2f9e151ee47cddcc25359ccf6ca28bef3daf116543343f63898ea514049"
                + "620ddb91616e9ec4891ade53fec4c06dc463a663e7c1008b2b9295a5478735e1fdb385a4fcc03485"
                + "3eb27602e96dfea7f620b22085f3e345ed57f33e044aeb4450fe10346459b8fc4d306bf59038bd17"
                + "2da6c32f4d6785c6e120a3da08988cf79a9e8a43fe97e6b64693776c209425a6d36cbfbf45ece68b"
                + "ffe7089bc5dc1c3ef265c0a88989ec279993a7e5c75f669768a1520791cc72f35268fa67654064d5"
                + "77d9d225da04c9694055df09cf3f14d8572a94c1793c32c0ecde034d24687a711d123f499f17f27f"
                + "ce41376100e854409ff647651633b1ec050cf4893e8fea4a956e2ba0e177dcaf8176974e21396337"
                + "6b5fec2e4dac76f8ef5f2371d9f3124eea512b934e5b09d6528d26c2f0d3767af7d3320d1e73b6a9"
                + "3ac4404a880603fdde06007a11f3ac554aceb0e40fff40702b6a5aa1fa492d630317ecc31aadd79e"
                + "6564c16a3f323f7fa4f58d4bfe27a09744f4ced12cddead3afa4dc6836afbbe2388dd933b8759d95"
                + "8d6334038eee7904bb907310726a0845ebddba81fb88db11c3853b251a"),
        Hex.decode("aa"));
  }

  public static SignatureTestVector[] createRsaSsaPkcs1TestVectors() {
    return exceptionIsBug(
        () ->
            new SignatureTestVector[] {
              createTestVector0(),
              createTestVector1(),
              createTestVector2(),
              createTestVector3(),
              createTestVector4(),
              createTestVector5()
            });
  }

  private RsaSsaPkcs1TestUtil() {}
}
