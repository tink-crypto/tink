// Copyright 2021 Google LLC
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

package com.google.crypto.tink.jwt;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.CleartextKeysetHandle;
import com.google.crypto.tink.JsonKeysetReader;
import com.google.crypto.tink.KeyTemplate;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.tinkkey.KeyAccess;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import java.io.IOException;
import java.security.GeneralSecurityException;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for JwkSetConverter */
@RunWith(JUnit4.class)
public final class JwkSetConverterTest {

  @Before
  public void setup() throws Exception {
    JwtSignatureConfig.register();
  }

  private static final String ES256_KEYSET =
      "{\"primaryKeyId\":282600252,\"key\":[{\"keyData\":{"
          + "\"typeUrl\":\"type.googleapis.com/google.crypto.tink.JwtEcdsaPublicKey\","
          + "\"value\":\"EAEaIBDPI66hjLHvjxmUJ2nyHIBDmdOtQ4gPsvWgYYgZ0gygIiBTEK0rTACpAb97m+mvtJKAk0"
          + "q3mHjPcUZm0C4EueDW4Q==\","
          + "\"keyMaterialType\":\"ASYMMETRIC_PUBLIC\""
          + "},\"status\":\"ENABLED\",\"keyId\":282600252,\"outputPrefixType\":\"RAW\"}]}";
  private static final String ES256_JWK_SET =
      "{\"keys\":[{"
          + "\"kty\":\"EC\","
          + "\"crv\":\"P-256\","
          + "\"x\":\"EM8jrqGMse-PGZQnafIcgEOZ061DiA-y9aBhiBnSDKA\","
          + "\"y\":\"UxCtK0wAqQG_e5vpr7SSgJNKt5h4z3FGZtAuBLng1uE\","
          + "\"use\":\"sig\",\"alg\":\"ES256\",\"key_ops\":[\"verify\"]}]}";

  private static final String ES384_KEYSET =
      "{\"primaryKeyId\":456087424,\"key\":[{\"keyData\":{"
          + "\"typeUrl\":\"type.googleapis.com/google.crypto.tink.JwtEcdsaPublicKey\","
          + "\"value\":\"EAIaMQDSjvWihoKGmr4nlDuI/KkvuPvEZr+B4bU0MuXQQXgyNMGApFm2iTeotv7LCSsG3mQiME"
          + "HIMGx4wa+Y8yeJQWMiSpukpPM7jP9GqaykZQQ2GY/NLg/n9+BJtntgvFhG5gWLTg==\","
          + "\"keyMaterialType\":\"ASYMMETRIC_PUBLIC\""
          + "},\"status\":\"ENABLED\",\"keyId\":456087424,\"outputPrefixType\":\"RAW\"}]}";
  private static final String ES384_JWK_SET =
      "{\"keys\":[{\"kty\":\"EC\",\"crv\":\"P-384\","
          + "\"x\":\"ANKO9aKGgoaavieUO4j8qS-4-8Rmv4HhtTQy5dBBeDI0wYCkWbaJN6i2_ssJKwbeZA\","
          + "\"y\":\"QcgwbHjBr5jzJ4lBYyJKm6Sk8zuM_0aprKRlBDYZj80uD-f34Em2e2C8WEbmBYtO\","
          + "\"use\":\"sig\",\"alg\":\"ES384\",\"key_ops\":[\"verify\"]}]}";

  private static final String ES512_KEYSET =
      "{\"primaryKeyId\":1570200439,\"key\":[{\"keyData\":{"
          + "\"typeUrl\":\"type.googleapis.com/google.crypto.tink.JwtEcdsaPublicKey\","
          + "\"value\":\"EAMaQgEV3nweRej6Z1/aPTqCkc1tQla5eVI68+qfwR1kB/wXCuYCB5otarhomUt64Fah/8Tjf0"
          + "WJHMZyFr86RUitiRQm1SJCATht/NOX8RcbaEr1MaH+0BFTaepvpTzSfQ04C2P8VCoURB3GeVKk4VQh8O/KLSYf"
          + "X+58bqEnaZ0G7W9qjHa2ols2\","
          + "\"keyMaterialType\":\"ASYMMETRIC_PUBLIC\""
          + "},\"status\":\"ENABLED\",\"keyId\":1570200439,\"outputPrefixType\":\"RAW\"}]}";
  private static final String ES512_JWK_SET =
      "{\"keys\":[{\"kty\":\"EC\",\"crv\":\"P-521\","
          + "\"x\":\"ARXefB5F6PpnX9o9OoKRzW1CVrl5Ujrz6p_BHWQH_BcK5gIHmi1quGiZS3rgVqH_xON_RYkcxnIWvz"
          + "pFSK2JFCbV\","
          + "\"y\":\"ATht_NOX8RcbaEr1MaH-0BFTaepvpTzSfQ04C2P8VCoURB3GeVKk4VQh8O_KLSYfX-58bqEnaZ0G7W"
          + "9qjHa2ols2\","
          + "\"use\":\"sig\",\"alg\":\"ES512\",\"key_ops\":[\"verify\"]}]}";

  private static final String RS256_KEYSET =
      "{\"primaryKeyId\":482168993,\"key\":[{\"keyData\":{"
          + "\"typeUrl\":\"type.googleapis.com/google.crypto.tink.JwtRsaSsaPkcs1PublicKey\","
          + "\"value\":\"EAEagQIAkspk37lGBqXmPPq2CL5KdDeRx7xFiTadpL3jc4nXaqftCtpM6qExfrc2JLaIsnwpwf"
          + "GMClfe/alIs2GrT9fpM8oDeCccvC39DzZhsSFnAELggi3hnWNKRLfSV0UJzBI+5hZ6ifUsv8W8mSHKlsVMmvOf"
          + "C2P5+l72qTwN6Le3hy6CxFp5s9pw011B7J3PU65sty6GI9sehB2B/n7nfiWw9YN5++pfwyoitzoMoVKOOpj7fF"
          + "q88f8ArpC7kR1SBTe20Bt1AmpZDT2Dmfmlb/Q1UFjj/F3C77NCNQ344ZcAEI42HY+uighy5GdKQRHMoTT1OzyD"
          + "G90ABjggQqDGW+zXzyIDAQAB\","
          + "\"keyMaterialType\":\"ASYMMETRIC_PUBLIC\""
          + "},\"status\":\"ENABLED\",\"keyId\":482168993,\"outputPrefixType\":\"RAW\"}]}";
  private static final String RS256_JWK_SET =
      "{\"keys\":[{\"kty\":\"RSA\","
          + "\"n\":\"AJLKZN-5Rgal5jz6tgi-SnQ3kce8RYk2naS943OJ12qn7QraTOqhMX63NiS2iLJ8KcHxjApX3v2pSL"
          + "Nhq0_X6TPKA3gnHLwt_Q82YbEhZwBC4IIt4Z1jSkS30ldFCcwSPuYWeon1LL_FvJkhypbFTJrznwtj-fpe9qk8"
          + "Dei3t4cugsRaebPacNNdQeydz1OubLcuhiPbHoQdgf5-534lsPWDefvqX8MqIrc6DKFSjjqY-3xavPH_AK6Qu5"
          + "EdUgU3ttAbdQJqWQ09g5n5pW_0NVBY4_xdwu-zQjUN-OGXABCONh2ProoIcuRnSkERzKE09Ts8gxvdAAY4IEKg"
          + "xlvs188\","
          + "\"e\":\"AQAB\",\"use\":\"sig\",\"alg\":\"RS256\",\"key_ops\":[\"verify\"]}]}";

  private static final String RS384_KEYSET =
      "{\"primaryKeyId\":333504275,\"key\":[{\"keyData\":{"
          + "\"typeUrl\":\"type.googleapis.com/google.crypto.tink.JwtRsaSsaPkcs1PublicKey\","
          + "\"value\":\"EAIagQMAnlBY5WD7gVQjNKvrS2whLKzt0Eql72B6haZ17eKifNn4S49eGdBy9RLj/mvHXAbacr"
          + "ngt9fzi0iv/WQ57jUmtO1b/wLt5LYk9APsBYjywDCIe+u9UouikP7c3SBqjjQijZ50jgYbMY6cL7s2Gx5lI1vl"
          + "GX3ZExLVYbNoI9VBFAWjSDefd6GugESxXQFnnO3p2GHOKryZLeDH/KzVacTq2/pVXKVH/9/EQzcLB0oYUljZ4v"
          + "YQ4HCAcwnUZbirsRwA0350Dz0Mlj+3+9sSAF8FPA+F/wlIBkPqjJ26b80V5FU4mBTzvYoXGTjkD7+bxH9p28hu"
          + "JSU96P4WdG5PYVwI1VEYwGipkUIpMWjJ7dXAtmltHzM9vkUt2bsBe9vyJjmRXyoC6mHSJbSyOm9Dd8BENobcUL"
          + "9h+aBoxruY+mU49kAHzzeAntn8C+vIrxN+X6N2EU9N8t9BF+mwYiBEsY54wx99RbRrY9yICfPBmQJGwXSxNCXB"
          + "RrbJyxkIVuqvACP5IgMBAAE=\","
          + "\"keyMaterialType\":\"ASYMMETRIC_PUBLIC\""
          + "},\"status\":\"ENABLED\",\"keyId\":333504275,\"outputPrefixType\":\"RAW\"}]}";
  private static final String RS384_JWK_SET =
      "{\"keys\":[{\"kty\":\"RSA\","
          + "\"n\":\"AJ5QWOVg-4FUIzSr60tsISys7dBKpe9geoWmde3ionzZ-EuPXhnQcvUS4_5rx1wG2nK54LfX84tIr_"
          + "1kOe41JrTtW_8C7eS2JPQD7AWI8sAwiHvrvVKLopD-3N0gao40Io2edI4GGzGOnC-7NhseZSNb5Rl92RMS1WGz"
          + "aCPVQRQFo0g3n3ehroBEsV0BZ5zt6dhhziq8mS3gx_ys1WnE6tv6VVylR__fxEM3CwdKGFJY2eL2EOBwgHMJ1G"
          + "W4q7EcANN-dA89DJY_t_vbEgBfBTwPhf8JSAZD6oydum_NFeRVOJgU872KFxk45A-_m8R_advIbiUlPej-FnRu"
          + "T2FcCNVRGMBoqZFCKTFoye3VwLZpbR8zPb5FLdm7AXvb8iY5kV8qAuph0iW0sjpvQ3fARDaG3FC_YfmgaMa7mP"
          + "plOPZAB883gJ7Z_AvryK8Tfl-jdhFPTfLfQRfpsGIgRLGOeMMffUW0a2PciAnzwZkCRsF0sTQlwUa2ycsZCFbq"
          + "rwAj-Q\","
          + "\"e\":\"AQAB\",\"use\":\"sig\",\"alg\":\"RS384\",\"key_ops\":[\"verify\"]}]}";

  private static final String RS512_KEYSET =
      "{\"primaryKeyId\":705596479,\"key\":[{\"keyData\":{"
          + "\"typeUrl\":\"type.googleapis.com/google.crypto.tink.JwtRsaSsaPkcs1PublicKey\","
          + "\"value\":\"EAMagQQAkKxZ9IRzF56gh47RXLJzQ6lffcnBmQSwvxUDJ0wHpKZzfAawOn1uidbgEoQ3XWOgtN"
          + "vi7QeKLE4GjQa5bY0xdRnu8nKjFcsvH+eu1sV8oVoZ984J5mT1mhwU6nt26p4xKyeapMhzYYNvKudQjQJ8SbpV"
          + "OFpEiJ7j0ECMUd4Q8mCUqWsrXYE8+1CcHjprsIxdot+haCARc72RBj9cLuBIhJNzlFXNmsYh8yoSiEYr/auRvg"
          + "/kIlNlnlOK/rJM/jMXbB6FuWdePrtqZ+ce2TVyARqjZJ0G0vZcPuvOhgS4LM7/Aeal84ZhIcHladSo/g8pK1eU"
          + "hnRqRXJpsltwux+1XVJeg2a0FQ0BN3Ft25uu5jhfvGWXeTkQOR7LbpbxKTI+vumSy9dmY4UrgAG37N8Xj5/Neq"
          + "BT51L3qE6tk2ZLoO7yjRjhADK5lnbb4iYWWvWd3kqyv0JVlxfDzjAaYtiduEUIdCe45MGk8DpCn9Lnjlunhm4Q"
          + "yQufK8k8UPiBbWNEODI8pjTSEjs0wyMqhegBKAvtVEhr029bg3Lv7YjN9FDvx4usuWGc16bXkTqNgCK4KzPG7P"
          + "wV120r6IVGflfpSkd5rrkzDY01fsP0mW57QCHA67bxqLUECr2dAfNzz6ddS9pqXQyXZWCyWKcvTFsGrr1oECwD"
          + "OmW+nUIHGklr9Q0iAwEAAQ==\","
          + "\"keyMaterialType\":\"ASYMMETRIC_PUBLIC\""
          + "},\"status\":\"ENABLED\",\"keyId\":705596479,\"outputPrefixType\":\"RAW\"}]}";
  private static final String RS512_JWK_SET =
      "{\"keys\":[{\"kty\":\"RSA\","
          + "\"n\":\"AJCsWfSEcxeeoIeO0Vyyc0OpX33JwZkEsL8VAydMB6Smc3wGsDp9bonW4BKEN11joLTb4u0HiixOBo"
          + "0GuW2NMXUZ7vJyoxXLLx_nrtbFfKFaGffOCeZk9ZocFOp7duqeMSsnmqTIc2GDbyrnUI0CfEm6VThaRIie49BA"
          + "jFHeEPJglKlrK12BPPtQnB46a7CMXaLfoWggEXO9kQY_XC7gSISTc5RVzZrGIfMqEohGK_2rkb4P5CJTZZ5Tiv"
          + "6yTP4zF2wehblnXj67amfnHtk1cgEao2SdBtL2XD7rzoYEuCzO_wHmpfOGYSHB5WnUqP4PKStXlIZ0akVyabJb"
          + "cLsftV1SXoNmtBUNATdxbdubruY4X7xll3k5EDkey26W8SkyPr7pksvXZmOFK4ABt-zfF4-fzXqgU-dS96hOrZ"
          + "NmS6Du8o0Y4QAyuZZ22-ImFlr1nd5Ksr9CVZcXw84wGmLYnbhFCHQnuOTBpPA6Qp_S545bp4ZuEMkLnyvJPFD4"
          + "gW1jRDgyPKY00hI7NMMjKoXoASgL7VRIa9NvW4Ny7-2IzfRQ78eLrLlhnNem15E6jYAiuCszxuz8FddtK-iFRn"
          + "5X6UpHea65Mw2NNX7D9Jlue0AhwOu28ai1BAq9nQHzc8-nXUvaal0Ml2VgslinL0xbBq69aBAsAzplvp1CBxpJ"
          + "a_UN\","
          + "\"e\":\"AQAB\",\"use\":\"sig\",\"alg\":\"RS512\",\"key_ops\":[\"verify\"]}]}";

  private static final String PS256_KEYSET =
      "{\"primaryKeyId\":1508587714,\"key\":[{\"keyData\":{"
          + "\"typeUrl\":\"type.googleapis.com/google.crypto.tink.JwtRsaSsaPssPublicKey\","
          + "\"value\":\"EAEagQMAj7Eud2n5G11qsdtjpgGWjW4cAKalSE1atm7d+Cp8biRX9wbmLJRMUvoO2j7Sp9Szx1"
          + "TMmksY2Ugf/7+Nv9fY7vBbmxOiBQVTvikWn0FgPwhFTXTz+9fhGjM6E6sdSOUzjM6nsPulKqOQ8Aed+TLIlgvw"
          + "uSTF4B5d6QkZWBymq7My6vV+epzWnoLpVDzCHh+c35r81Pyrj6tiTPQzPLN2ixeanclMjx8deNwlak3vwBdMDg"
          + "wQ63rVCo2eWDS/BYK4rG22luSTDVfQVHU1NXlwXEnb/eONFSF6ZbD6JXFMT3uHT4okTOrX4Kd34stbPIUtZFUy"
          + "3XiSeCGtghBXLMf/ge113Q9WDJ+RN1Xa4vgHJCO0+VO+cAugVkiu9UgsPP8o/r7tA2aP/Ps8EHYa1IaZg75vnr"
          + "MZPvsTH7WG2SjSgW9GLLsbNJLFFqLFMwPuZPe8BbgvimPdStXasX/PN6DLKoK2PaT0I+iLK9mRi1Z4OjFbl9KA"
          + "ZXXElhAQTzrEI2adIgMBAAE=\","
          + "\"keyMaterialType\":\"ASYMMETRIC_PUBLIC\""
          + "},\"status\":\"ENABLED\",\"keyId\":1508587714,\"outputPrefixType\":\"RAW\"}]}";

  private static final String PS256_JWK_SET =
      "{\"keys\":[{\"kty\":\"RSA\","
          + "\"n\":\"AI-xLndp-RtdarHbY6YBlo1uHACmpUhNWrZu3fgqfG4kV_cG5iyUTFL6Dto-0qfUs8dUzJpLGNlIH_"
          + "-_jb_X2O7wW5sTogUFU74pFp9BYD8IRU108_vX4RozOhOrHUjlM4zOp7D7pSqjkPAHnfkyyJYL8LkkxeAeXekJ"
          + "GVgcpquzMur1fnqc1p6C6VQ8wh4fnN-a_NT8q4-rYkz0MzyzdosXmp3JTI8fHXjcJWpN78AXTA4MEOt61QqNnl"
          + "g0vwWCuKxttpbkkw1X0FR1NTV5cFxJ2_3jjRUhemWw-iVxTE97h0-KJEzq1-Cnd-LLWzyFLWRVMt14knghrYIQ"
          + "VyzH_4Htdd0PVgyfkTdV2uL4ByQjtPlTvnALoFZIrvVILDz_KP6-7QNmj_z7PBB2GtSGmYO-b56zGT77Ex-1ht"
          + "ko0oFvRiy7GzSSxRaixTMD7mT3vAW4L4pj3UrV2rF_zzegyyqCtj2k9CPoiyvZkYtWeDoxW5fSgGV1xJYQEE86"
          + "xCNmnQ\","
          + "\"e\":\"AQAB\",\"use\":\"sig\",\"alg\":\"PS256\",\"key_ops\":[\"verify\"]}]}";

  private static final String PS384_KEYSET =
      "{\"primaryKeyId\":1042230435,\"key\":[{\"keyData\":{"
          + "\"typeUrl\":\"type.googleapis.com/google.crypto.tink.JwtRsaSsaPssPublicKey\","
          + "\"value\":\"EAIagQMAv6a0OergWYmY1k6l6vx6Of5+RxCeeQ9jMTXQyvO0GCgMDExxtqVS8S25ehZ5LNDIiG"
          + "jhE3v2++D7QEjnzOC5UqI1ZwPxUBSrOaf5oDbJ9vBc2c7wDyJhRV8UobQSpzunD4kXypVhytjwRdiP61vG0C/e"
          + "L0x+LijtM/XVee1Y+5mWrypVrB6EHKtdkMx2WIYNpsFOForFrr6JzLbWfDRWoqbCXKYivnw+CSE38ddW1XsrAT"
          + "76E2Vf+womuwyBbkjLaiWvNxNFBTap2IaBLKAni6x7pqYCeu1n9eMUi41oz9QM8xfOvpH+wubc2PjwyTsb1FDT"
          + "LnhV36tQLTVGdQdCDMF2Z8Agrnio3n1SFjSbYgFyVtpCwFKM2Z0zfO7k9jVbYYkzglzkJfp/lQrsuWqe4CVJjF"
          + "E1H4BxcU7L0j8755kGJI08h1b7LPgqJcPgtHjcqbxHFU2yOf7mNGlW7YTnoQBO0StzQUk7kEw3X0+niEwX/L8j"
          + "qW4YMbxrGdAfkTnPIgMBAAE=\","
          + "\"keyMaterialType\":\"ASYMMETRIC_PUBLIC\""
          + "},\"status\":\"ENABLED\",\"keyId\":1042230435,\"outputPrefixType\":\"RAW\"}]}";

  private static final String PS384_JWK_SET =
      "{\"keys\":[{\"kty\":\"RSA\","
          + "\"n\":\"AL-mtDnq4FmJmNZOper8ejn-fkcQnnkPYzE10MrztBgoDAxMcbalUvEtuXoWeSzQyIho4RN79vvg-0"
          + "BI58zguVKiNWcD8VAUqzmn-aA2yfbwXNnO8A8iYUVfFKG0Eqc7pw-JF8qVYcrY8EXYj-tbxtAv3i9Mfi4o7TP1"
          + "1XntWPuZlq8qVawehByrXZDMdliGDabBThaKxa6-icy21nw0VqKmwlymIr58PgkhN_HXVtV7KwE--hNlX_sKJr"
          + "sMgW5Iy2olrzcTRQU2qdiGgSygJ4use6amAnrtZ_XjFIuNaM_UDPMXzr6R_sLm3Nj48Mk7G9RQ0y54Vd-rUC01"
          + "RnUHQgzBdmfAIK54qN59UhY0m2IBclbaQsBSjNmdM3zu5PY1W2GJM4Jc5CX6f5UK7LlqnuAlSYxRNR-AcXFOy9"
          + "I_O-eZBiSNPIdW-yz4KiXD4LR43Km8RxVNsjn-5jRpVu2E56EATtErc0FJO5BMN19Pp4hMF_y_I6luGDG8axnQ"
          + "H5E5zw\","
          + "\"e\":\"AQAB\",\"use\":\"sig\",\"alg\":\"PS384\",\"key_ops\":[\"verify\"]}]}";

  private static final String PS512_KEYSET =
      "{\"primaryKeyId\":257081135,\"key\":[{\"keyData\":{"
          + "\"typeUrl\":\"type.googleapis.com/google.crypto.tink.JwtRsaSsaPssPublicKey\","
          + "\"value\":\"EAMagQQAnOUQvBwNRgeI3zlzIhVo4NzFVCsQn9hd2EIclz6cWBRMFr4EX5lXLK0StSIB7EQP4c"
          + "iHa+vr59sOgMFMC2kiXRUXNtl99QhGwH0YjbWeDC50PKEAjH1hhhPgSw2dFcUVs4jbScDrwNn1sQ8rkgSNczvQ"
          + "NpV1MtBhS/CC1PxVF88JaejG2zr+unoFlw7xnqxBWMzNrMHZHwqga2vL3inSbvA/RGQjnE2DzQSwZkXthGSwYB"
          + "jOYbGawMN4onkAx/myHMyTg/TLAqG9GUyB0DVelvVoGZG/QJBY2Fp2FlpOQRKeBr6pC7Lk8zZL4GJk264KoOpG"
          + "8v1t7PveN+STIdTE2D548K+GDOvsvrO4ZhofS/iqN9xLucuU1HkqKUqyLvMxsWum8Zhp7zinFdBnDOgeheOHUg"
          + "N/iwjupk6u1Svt+RWNJsfb2l0jrvzf0cRMbPeLZRmpDwBxBvXWo61u6uaBEVb+ooZ6K5+hx3Rld7wXktjYIZzH"
          + "qUr39P5yTw28b8Y2dPFWR4vwr2/0zBxcDmTRRtQ7vPOtZPD0/LVIXkgbBiLILpycnucWt9Lq9Hc62KFiTQOAuu"
          + "Oxz7ObBegXjnFupiZZ9PyzO5WgT9lRpH7U7tzGLAjV+AUpjH6HA1o6bRLKOHFBPS+I9IqAYb/RpF6M/6hCmC2R"
          + "z64yYzR3y4vHKGMiAwEAAQ==\","
          + "\"keyMaterialType\":\"ASYMMETRIC_PUBLIC\""
          + "},\"status\":\"ENABLED\",\"keyId\":257081135,\"outputPrefixType\":\"RAW\"}]}";

  private static final String PS512_JWK_SET =
      "{\"keys\":[{\"kty\":\"RSA\","
          + "\"n\":\"AJzlELwcDUYHiN85cyIVaODcxVQrEJ_YXdhCHJc-nFgUTBa-BF-ZVyytErUiAexED-HIh2vr6-fbDo"
          + "DBTAtpIl0VFzbZffUIRsB9GI21ngwudDyhAIx9YYYT4EsNnRXFFbOI20nA68DZ9bEPK5IEjXM70DaVdTLQYUvw"
          + "gtT8VRfPCWnoxts6_rp6BZcO8Z6sQVjMzazB2R8KoGtry94p0m7wP0RkI5xNg80EsGZF7YRksGAYzmGxmsDDeK"
          + "J5AMf5shzMk4P0ywKhvRlMgdA1Xpb1aBmRv0CQWNhadhZaTkESnga-qQuy5PM2S-BiZNuuCqDqRvL9bez73jfk"
          + "kyHUxNg-ePCvhgzr7L6zuGYaH0v4qjfcS7nLlNR5KilKsi7zMbFrpvGYae84pxXQZwzoHoXjh1IDf4sI7qZOrt"
          + "Ur7fkVjSbH29pdI67839HETGz3i2UZqQ8AcQb11qOtburmgRFW_qKGeiufocd0ZXe8F5LY2CGcx6lK9_T-ck8N"
          + "vG_GNnTxVkeL8K9v9MwcXA5k0UbUO7zzrWTw9Py1SF5IGwYiyC6cnJ7nFrfS6vR3OtihYk0DgLrjsc-zmwXoF4"
          + "5xbqYmWfT8szuVoE_ZUaR-1O7cxiwI1fgFKYx-hwNaOm0SyjhxQT0viPSKgGG_0aRejP-oQpgtkc-uMmM0d8uL"
          + "xyhj\","
          + "\"e\":\"AQAB\",\"use\":\"sig\",\"alg\":\"PS512\",\"key_ops\":[\"verify\"]}]}";

  private static final String PRIVATEKEY_KEYSET =
      "{\"primaryKeyId\":152493399,\"key\":[{\"keyData\":{"
          + "\"typeUrl\":\"type.googleapis.com/google.crypto.tink.JwtEcdsaPrivateKey\","
          + "\"value\":\"EkYQARogaHkaakArEB51RyZ236S5x3BxaNTFycWuXIGZF8adZ2UiIFlZT7MFogZ8ARbS1URIAP"
          + "cpw8A0g2uwAHRkBqGUiCU2GiBI4jtU/59Zajohgeezi2BXB13O8IJh8V3b0itq5zyy5Q==\","
          + "\"keyMaterialType\":\"ASYMMETRIC_PRIVATE\""
          + "},\"status\":\"ENABLED\",\"keyId\":152493399,\"outputPrefixType\":\"RAW\"}]}";

  private static final String KEYSET_WITH_TWO_KEYS =
      "{\"primaryKeyId\":282600252,\"key\":["
          + "{\"keyData\":{"
          + "\"typeUrl\":\"type.googleapis.com/google.crypto.tink.JwtEcdsaPublicKey\","
          + "\"value\":\"EAEaIBDPI66hjLHvjxmUJ2nyHIBDmdOtQ4gPsvWgYYgZ0gygIiBTEK0rTACpAb97m+mvtJKAk0"
          + "q3mHjPcUZm0C4EueDW4Q==\","
          + "\"keyMaterialType\":\"ASYMMETRIC_PUBLIC\""
          + "},\"status\":\"ENABLED\",\"keyId\":282600252,\"outputPrefixType\":\"RAW\"},"
          + "{\"keyData\":{"
          + "\"typeUrl\":\"type.googleapis.com/google.crypto.tink.JwtRsaSsaPkcs1PublicKey\","
          + "\"value\":\"EAEagQIAkspk37lGBqXmPPq2CL5KdDeRx7xFiTadpL3jc4nXaqftCtpM6qExfrc2JLaIsnwpwf"
          + "GMClfe/alIs2GrT9fpM8oDeCccvC39DzZhsSFnAELggi3hnWNKRLfSV0UJzBI+5hZ6ifUsv8W8mSHKlsVMmvOf"
          + "C2P5+l72qTwN6Le3hy6CxFp5s9pw011B7J3PU65sty6GI9sehB2B/n7nfiWw9YN5++pfwyoitzoMoVKOOpj7fF"
          + "q88f8ArpC7kR1SBTe20Bt1AmpZDT2Dmfmlb/Q1UFjj/F3C77NCNQ344ZcAEI42HY+uighy5GdKQRHMoTT1OzyD"
          + "G90ABjggQqDGW+zXzyIDAQAB\","
          + "\"keyMaterialType\":\"ASYMMETRIC_PUBLIC\""
          + "},\"status\":\"ENABLED\",\"keyId\":482168993,\"outputPrefixType\":\"RAW\"}]}";
  private static final String JWK_SET_WITH_TWO_KEYS =
      "{\"keys\":[{"
          + "\"kty\":\"EC\","
          + "\"crv\":\"P-256\","
          + "\"x\":\"EM8jrqGMse-PGZQnafIcgEOZ061DiA-y9aBhiBnSDKA\","
          + "\"y\":\"UxCtK0wAqQG_e5vpr7SSgJNKt5h4z3FGZtAuBLng1uE\","
          + "\"use\":\"sig\",\"alg\":\"ES256\",\"key_ops\":[\"verify\"]},"
          + "{\"kty\":\"RSA\","
          + "\"n\":\"AJLKZN-5Rgal5jz6tgi-SnQ3kce8RYk2naS943OJ12qn7QraTOqhMX63NiS2iLJ8KcHxjApX3v2pSL"
          + "Nhq0_X6TPKA3gnHLwt_Q82YbEhZwBC4IIt4Z1jSkS30ldFCcwSPuYWeon1LL_FvJkhypbFTJrznwtj-fpe9qk8"
          + "Dei3t4cugsRaebPacNNdQeydz1OubLcuhiPbHoQdgf5-534lsPWDefvqX8MqIrc6DKFSjjqY-3xavPH_AK6Qu5"
          + "EdUgU3ttAbdQJqWQ09g5n5pW_0NVBY4_xdwu-zQjUN-OGXABCONh2ProoIcuRnSkERzKE09Ts8gxvdAAY4IEKg"
          + "xlvs188\","
          + "\"e\":\"AQAB\",\"use\":\"sig\",\"alg\":\"RS256\",\"key_ops\":[\"verify\"]}]}";


  private static void assertEqualJwkSets(String jwkSet1, String jwkSet2) throws Exception {
    // Consider these strings equal, if their equal after parsing them.
    // The keys may have any order.
    JsonObject parsedjwkSet1 = JsonParser.parseString(jwkSet1).getAsJsonObject();
    JsonObject parsedjwkSet2 = JsonParser.parseString(jwkSet2).getAsJsonObject();
    JsonArray keys1 = parsedjwkSet1.remove("keys").getAsJsonArray();
    JsonArray keys2 = parsedjwkSet2.remove("keys").getAsJsonArray();
    assertThat(keys1).containsExactlyElementsIn(keys2);
    assertThat(parsedjwkSet1).isEqualTo(parsedjwkSet2);
  }

  @Test
  public void assertEqualJwkSets_equal() throws Exception {
    // Whitespace, order of object properties, and order of keys is ignored.
    assertEqualJwkSets(
        "{\"keys\":[{\"kty\": \"EC\"},     {\"e\":\"f\",\"kty\": \"RSA\"}]}",
        "{\"keys\":[{\"kty\":\"RSA\",\"e\":\"f\"}, {\"kty\":\"EC\"}]}");
  }

  @Test
  public void assertEqualJwkSets_notEequal() throws Exception {
    // Order of arrays (except "keys" array) is not ignored.
    assertThrows(
        AssertionError.class,
        () ->
            assertEqualJwkSets(
                "{\"keys\":[{\"kty\":\"EC\",\"key_ops\":[\"b\",\"c\"]}]}",
                "{\"keys\":[{\"kty\":\"EC\",\"key_ops\":[\"c\",\"b\"]}]}"));
  }

  private static String convertToJwkSet(String jsonKeyset) throws Exception {
    KeysetHandle handle = CleartextKeysetHandle.read(JsonKeysetReader.withString(jsonKeyset));
    return JwkSetConverter.fromKeysetHandle(handle, KeyAccess.publicAccess());
  }

  @Test
  public void convertEcdsaKeysets_success() throws Exception {
    assertEqualJwkSets(convertToJwkSet(ES256_KEYSET), ES256_JWK_SET);
    assertEqualJwkSets(convertToJwkSet(ES384_KEYSET), ES384_JWK_SET);
    assertEqualJwkSets(convertToJwkSet(ES512_KEYSET), ES512_JWK_SET);
  }

  @Test
  public void convertRsaSsaPkcs1Keysets_success() throws Exception {
    assertEqualJwkSets(convertToJwkSet(RS256_KEYSET), RS256_JWK_SET);
    assertEqualJwkSets(convertToJwkSet(RS384_KEYSET), RS384_JWK_SET);
    assertEqualJwkSets(convertToJwkSet(RS512_KEYSET), RS512_JWK_SET);
  }

  @Test
  public void convertRsaSsaPssKeysets_success() throws Exception {
    assertEqualJwkSets(convertToJwkSet(PS256_KEYSET), PS256_JWK_SET);
    assertEqualJwkSets(convertToJwkSet(PS384_KEYSET), PS384_JWK_SET);
    assertEqualJwkSets(convertToJwkSet(PS512_KEYSET), PS512_JWK_SET);
  }

  @Test
  public void toKeysetHandleFromKeysetHandle_success() throws Exception {
    assertEqualJwkSets(
        JwkSetConverter.fromKeysetHandle(
            JwkSetConverter.toKeysetHandle(ES256_JWK_SET, KeyAccess.publicAccess()),
            KeyAccess.publicAccess()),
        ES256_JWK_SET);
    assertEqualJwkSets(
        JwkSetConverter.fromKeysetHandle(
            JwkSetConverter.toKeysetHandle(ES384_JWK_SET, KeyAccess.publicAccess()),
            KeyAccess.publicAccess()),
        ES384_JWK_SET);
    assertEqualJwkSets(
        JwkSetConverter.fromKeysetHandle(
            JwkSetConverter.toKeysetHandle(ES512_JWK_SET, KeyAccess.publicAccess()),
            KeyAccess.publicAccess()),
        ES512_JWK_SET);
    assertEqualJwkSets(
        JwkSetConverter.fromKeysetHandle(
            JwkSetConverter.toKeysetHandle(RS256_JWK_SET, KeyAccess.publicAccess()),
            KeyAccess.publicAccess()),
        RS256_JWK_SET);
    assertEqualJwkSets(
        JwkSetConverter.fromKeysetHandle(
            JwkSetConverter.toKeysetHandle(RS384_JWK_SET, KeyAccess.publicAccess()),
            KeyAccess.publicAccess()),
        RS384_JWK_SET);
    assertEqualJwkSets(
        JwkSetConverter.fromKeysetHandle(
            JwkSetConverter.toKeysetHandle(RS512_JWK_SET, KeyAccess.publicAccess()),
            KeyAccess.publicAccess()),
        RS512_JWK_SET);
    assertEqualJwkSets(
        JwkSetConverter.fromKeysetHandle(
            JwkSetConverter.toKeysetHandle(PS256_JWK_SET, KeyAccess.publicAccess()),
            KeyAccess.publicAccess()),
        PS256_JWK_SET);
    assertEqualJwkSets(
        JwkSetConverter.fromKeysetHandle(
            JwkSetConverter.toKeysetHandle(PS384_JWK_SET, KeyAccess.publicAccess()),
            KeyAccess.publicAccess()),
        PS384_JWK_SET);
    assertEqualJwkSets(
        JwkSetConverter.fromKeysetHandle(
            JwkSetConverter.toKeysetHandle(PS512_JWK_SET, KeyAccess.publicAccess()),
            KeyAccess.publicAccess()),
        PS512_JWK_SET);
  }

  @Test
  public void convertTinkToJwksTokenVerification_success() throws Exception {
    // TODO(juerg): Use parametrized tests once b/26110951 is resolved.
    KeyTemplate[] templates = new KeyTemplate[] {
      JwtEcdsaSignKeyManager.jwtES256Template(),
      JwtEcdsaSignKeyManager.jwtES384Template(),
      JwtEcdsaSignKeyManager.jwtES512Template(),
      JwtRsaSsaPkcs1SignKeyManager.jwtRs256_2048_F4_Template(),
      JwtRsaSsaPkcs1SignKeyManager.jwtRs256_3072_F4_Template(),
      JwtRsaSsaPkcs1SignKeyManager.jwtRs384_3072_F4_Template(),
      JwtRsaSsaPkcs1SignKeyManager.jwtRs512_4096_F4_Template(),
      JwtRsaSsaPssSignKeyManager.jwtPs256_2048_F4_Template(),
      JwtRsaSsaPssSignKeyManager.jwtPs256_3072_F4_Template(),
      JwtRsaSsaPssSignKeyManager.jwtPs384_3072_F4_Template(),
      JwtRsaSsaPssSignKeyManager.jwtPs512_4096_F4_Template(),
    };
    for (KeyTemplate template : templates) {
      KeysetHandle keysetHandle = KeysetHandle.generateNew(template);

      String jwksString =
          JwkSetConverter.fromKeysetHandle(
              keysetHandle.getPublicKeysetHandle(), KeyAccess.publicAccess());

      KeysetHandle publicKeysetHandle =
          JwkSetConverter.toKeysetHandle(jwksString, KeyAccess.publicAccess());

      JwtPublicKeySign signer = keysetHandle.getPrimitive(JwtPublicKeySign.class);
      JwtPublicKeyVerify verifier = publicKeysetHandle.getPrimitive(JwtPublicKeyVerify.class);

      RawJwt rawToken = new RawJwt.Builder().setJwtId("jwtId").build();
      String signedCompact = signer.signAndEncode(rawToken);
      JwtValidator validator = new JwtValidator.Builder().build();
      VerifiedJwt verifiedToken = verifier.verifyAndDecode(signedCompact, validator);
      assertThat(verifiedToken.getJwtId()).isEqualTo("jwtId");
    }
  }

  @Test
  public void keysetWithTwoKeys_fromKeysetHandleSuccess() throws Exception {
    assertEqualJwkSets(convertToJwkSet(KEYSET_WITH_TWO_KEYS), JWK_SET_WITH_TWO_KEYS);
  }

  @Test
  public void primaryKeyIdMissing_fromKeysetHandleSuccess() throws Exception {
    String keyset = ES256_KEYSET.replace("\"primaryKeyId\":282600252,", "");
    assertEqualJwkSets(convertToJwkSet(keyset), ES256_JWK_SET);
  }

  @Test
  public void tinkEcdsaKeysets_fromKeysetHandleFails() throws Exception {
    String keyset = ES256_KEYSET.replace("RAW", "TINK");
    assertThrows(IOException.class, () -> convertToJwkSet(keyset));
  }

  @Test
  public void legacyEcdsaKeysets_fromKeysetHandleFails() throws Exception {
    String keyset = ES256_KEYSET.replace("RAW", "LEGACY");
    assertThrows(IOException.class, () -> convertToJwkSet(keyset));
  }

  @Test
  public void crunchyEcdsaKeysets_fromKeysetHandleFails() throws Exception {
    String keyset = ES256_KEYSET.replace("RAW", "CRUNCHY");
    assertThrows(IOException.class, () -> convertToJwkSet(keyset));
  }

  @Test
  public void disabledKeysets_fromKeysetHandleReturnsEmptySet() throws Exception {
    String keyset = ES256_KEYSET.replace("ENABLED", "DISABLED");
    assertEqualJwkSets(convertToJwkSet(keyset), "{\"keys\":[]}");
  }

  @Test
  public void privateKey_fromKeysetHandleFails() throws Exception {
    assertThrows(GeneralSecurityException.class, () -> convertToJwkSet(PRIVATEKEY_KEYSET));
  }

  @Test
  public void tinkRsaSsaPkcs1Keysets_fromKeysetHandleFails() throws Exception {
    String keyset = RS256_KEYSET.replace("RAW", "TINK");
    assertThrows(IOException.class, () -> convertToJwkSet(keyset));
  }

  @Test
  public void legacyRsaSsaPkcs1Keysets_fromKeysetHandleFails() throws Exception {
    String keyset = RS256_KEYSET.replace("RAW", "LEGACY");
    assertThrows(IOException.class, () -> convertToJwkSet(keyset));
  }

  @Test
  public void crunchyRsaSsaPkcs1Keysets_fromKeysetHandleFails() throws Exception {
    String keyset = RS256_KEYSET.replace("RAW", "CRUNCHY");
    assertThrows(IOException.class, () -> convertToJwkSet(keyset));
  }

  @Test
  public void tinkRsaSsaPssKeysets_fromKeysetHandleFails() throws Exception {
    String keyset = PS256_KEYSET.replace("RAW", "TINK");
    assertThrows(IOException.class, () -> convertToJwkSet(keyset));
  }

  @Test
  public void legacyRsaSsaPssKeysets_fromKeysetHandleFails() throws Exception {
    String keyset = PS256_KEYSET.replace("RAW", "LEGACY");
    assertThrows(IOException.class, () -> convertToJwkSet(keyset));
  }

  @Test
  public void crunchyRsaSsaPssKeysets_fromKeysetHandleFails() throws Exception {
    String keyset = PS256_KEYSET.replace("RAW", "CRUNCHY");
    assertThrows(IOException.class, () -> convertToJwkSet(keyset));
  }

  @Test
  public void ecdsaWithoutUseAndKeyOps_toKeysetHandleSuccess() throws Exception {
    String jwksString =
        "{"
            + "\"keys\":[{"
            + "\"kty\":\"EC\","
            + "\"crv\":\"P-256\","
            + "\"x\":\"KUPydf4k4cS5EGS82npjEUxKIiBfUGP3wlN49A2GxTY\","
            + "\"y\":\"b22m_Y4sT-jUJSxBVqjrW_DxWyBLopxYHTuFVfx70ZI\","
            + "\"alg\":\"ES256\""
            + "}]}";
    // ignore returned value, we only test that it worked.
    JwkSetConverter.toKeysetHandle(jwksString, KeyAccess.publicAccess());
  }

  @Test
  public void ecdsaPrivateKey_fails() throws Exception {
    // Example from https://datatracker.ietf.org/doc/html/rfc7517#appendix-A.2
    String jwksString =
        "{"
            + "\"keys\":[{"
            + "\"kty\":\"EC\","
            + "\"crv\":\"P-256\","
            + "\"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\","
            + "\"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\","
            + "\"d\":\"870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE\","
            + "\"alg\":\"ES256\""
            + "}]}";
    assertThrows(
        UnsupportedOperationException.class,
        () -> JwkSetConverter.toKeysetHandle(jwksString, KeyAccess.publicAccess()));
  }

  @Test
  public void ecdsaWithUnknownField_toKeysetHandleSuccess() throws Exception {
    String jwksString =
        "{"
            + "\"keys\":[{"
            + "\"kty\":\"EC\","
            + "\"crv\":\"P-256\","
            + "\"x\":\"KUPydf4k4cS5EGS82npjEUxKIiBfUGP3wlN49A2GxTY\","
            + "\"y\":\"b22m_Y4sT-jUJSxBVqjrW_DxWyBLopxYHTuFVfx70ZI\","
            + "\"alg\":\"ES256\","
            + "\"unknown\":1234,"
            + "\"use\":\"sig\","
            + "\"key_ops\":[\"verify\"]"
            + "}]}";
    // ignore returned value, we only test that it worked.
    JwkSetConverter.toKeysetHandle(jwksString, KeyAccess.publicAccess());
  }

  @Test
  public void ecdsaWithoutAlg_toKeysetHandleFails() throws Exception {
    String jwksString =
        "{"
            + "\"keys\":[{"
            + "\"kty\":\"EC\","
            + "\"crv\":\"P-256\","
            + "\"x\":\"KUPydf4k4cS5EGS82npjEUxKIiBfUGP3wlN49A2GxTY\","
            + "\"y\":\"b22m_Y4sT-jUJSxBVqjrW_DxWyBLopxYHTuFVfx70ZI\","
            + "\"use\":\"sig\","
            + "\"key_ops\":[\"verify\"]"
            + "}]}";
    assertThrows(
        IOException.class,
        () -> JwkSetConverter.toKeysetHandle(jwksString, KeyAccess.publicAccess()));
  }

  @Test
  public void ecdsaWithoutKty_toKeysetHandleFails() throws Exception {
    String jwksString =
        "{"
            + "\"keys\":[{"
            + "\"crv\":\"P-256\","
            + "\"x\":\"KUPydf4k4cS5EGS82npjEUxKIiBfUGP3wlN49A2GxTY\","
            + "\"y\":\"b22m_Y4sT-jUJSxBVqjrW_DxWyBLopxYHTuFVfx70ZI\","
            + "\"use\":\"sig\","
            + "\"alg\":\"ES256\","
            + "\"key_ops\":[\"verify\"]"
            + "}]}";
    assertThrows(
        IOException.class,
        () -> JwkSetConverter.toKeysetHandle(jwksString, KeyAccess.publicAccess()));
  }

  @Test
  public void ecdsaWithoutCrv_toKeysetHandleFails() throws Exception {
    String jwksString =
        "{"
            + "\"keys\":[{"
            + "\"kty\":\"EC\","
            + "\"x\":\"KUPydf4k4cS5EGS82npjEUxKIiBfUGP3wlN49A2GxTY\","
            + "\"y\":\"b22m_Y4sT-jUJSxBVqjrW_DxWyBLopxYHTuFVfx70ZI\","
            + "\"use\":\"sig\","
            + "\"alg\":\"ES256\","
            + "\"key_ops\":[\"verify\"]"
            + "}]}";
    assertThrows(
        IOException.class,
        () -> JwkSetConverter.toKeysetHandle(jwksString, KeyAccess.publicAccess()));
  }

  @Test
  public void ecdsaWithSmallX_getPrimitiveFails() throws Exception {
    String jwksString =
        "{"
            + "\"keys\":[{"
            + "\"kty\":\"EC\","
            + "\"crv\":\"P-256\","
            + "\"x\":\"AAAwOQ\","
            + "\"y\":\"b22m_Y4sT-jUJSxBVqjrW_DxWyBLopxYHTuFVfx70ZI\","
            + "\"use\":\"sig\","
            + "\"alg\":\"ES256\","
            + "\"key_ops\":[\"verify\"]"
            + "}]}";
    KeysetHandle handle = JwkSetConverter.toKeysetHandle(jwksString, KeyAccess.publicAccess());
    assertThrows(
        GeneralSecurityException.class, () -> handle.getPrimitive(JwtPublicKeyVerify.class));
  }

  @Test
  public void ecdsaWithSmallY_getPrimitiveFails() throws Exception {
    String jwksString =
        "{"
            + "\"keys\":[{"
            + "\"kty\":\"EC\","
            + "\"crv\":\"P-256\","
            + "\"x\":\"KUPydf4k4cS5EGS82npjEUxKIiBfUGP3wlN49A2GxTY\","
            + "\"y\":\"AAAwOQ\","
            + "\"use\":\"sig\","
            + "\"alg\":\"ES256\","
            + "\"key_ops\":[\"verify\"]"
            + "}]}";
    KeysetHandle handle = JwkSetConverter.toKeysetHandle(jwksString, KeyAccess.publicAccess());
    assertThrows(
        GeneralSecurityException.class, () -> handle.getPrimitive(JwtPublicKeyVerify.class));
  }

  @Test
  public void ecdsaWithInvalidKty_toKeysetHandleFails() throws Exception {
    String jwksString =
        "{"
            + "\"keys\":[{"
            + "\"kty\":\"RSA\","
            + "\"crv\":\"P-256\","
            + "\"x\":\"KUPydf4k4cS5EGS82npjEUxKIiBfUGP3wlN49A2GxTY\","
            + "\"y\":\"b22m_Y4sT-jUJSxBVqjrW_DxWyBLopxYHTuFVfx70ZI\","
            + "\"use\":\"sig\","
            + "\"alg\":\"ES256\","
            + "\"key_ops\":[\"verify\"]"
            + "}]}";
    assertThrows(
        IOException.class,
        () -> JwkSetConverter.toKeysetHandle(jwksString, KeyAccess.publicAccess()));
  }

  @Test
  public void ecdsaWithInvalidCrv_toKeysetHandleFails() throws Exception {
    String jwksString =
        "{"
            + "\"keys\":[{"
            + "\"kty\":\"EC\","
            + "\"crv\":\"P-384\","
            + "\"x\":\"KUPydf4k4cS5EGS82npjEUxKIiBfUGP3wlN49A2GxTY\","
            + "\"y\":\"b22m_Y4sT-jUJSxBVqjrW_DxWyBLopxYHTuFVfx70ZI\","
            + "\"use\":\"sig\","
            + "\"alg\":\"ES256\","
            + "\"key_ops\":[\"verify\"]"
            + "}]}";
    assertThrows(
        IOException.class,
        () -> JwkSetConverter.toKeysetHandle(jwksString, KeyAccess.publicAccess()));
  }

  @Test
  public void ecdsaWithInvalidUse_toKeysetHandleFails() throws Exception {
    String jwksString =
        "{"
            + "\"keys\":[{"
            + "\"kty\":\"EC\","
            + "\"crv\":\"P-256\","
            + "\"x\":\"KUPydf4k4cS5EGS82npjEUxKIiBfUGP3wlN49A2GxTY\","
            + "\"y\":\"b22m_Y4sT-jUJSxBVqjrW_DxWyBLopxYHTuFVfx70ZI\","
            + "\"use\":\"invalid\","
            + "\"alg\":\"ES256\","
            + "\"key_ops\":[\"verify\"]"
            + "}]}";
    assertThrows(
        IOException.class,
        () -> JwkSetConverter.toKeysetHandle(jwksString, KeyAccess.publicAccess()));
  }

  @Test
  public void ecdsaWithInvalidKeyOps_toKeysetHandleFails() throws Exception {
    String jwksString =
        "{"
            + "\"keys\":[{"
            + "\"kty\":\"EC\","
            + "\"crv\":\"P-256\","
            + "\"x\":\"KUPydf4k4cS5EGS82npjEUxKIiBfUGP3wlN49A2GxTY\","
            + "\"y\":\"b22m_Y4sT-jUJSxBVqjrW_DxWyBLopxYHTuFVfx70ZI\","
            + "\"use\":\"sig\","
            + "\"alg\":\"ES256\","
            + "\"key_ops\":[\"invalid\"]"
            + "}]}";
    assertThrows(
        IOException.class,
        () -> JwkSetConverter.toKeysetHandle(jwksString, KeyAccess.publicAccess()));
  }

  @Test
  public void ecdsaWithStringKeyOps_toKeysetHandleFails() throws Exception {
    String jwksString =
        "{"
            + "\"keys\":[{"
            + "\"kty\":\"EC\","
            + "\"crv\":\"P-256\","
            + "\"x\":\"KUPydf4k4cS5EGS82npjEUxKIiBfUGP3wlN49A2GxTY\","
            + "\"y\":\"b22m_Y4sT-jUJSxBVqjrW_DxWyBLopxYHTuFVfx70ZI\","
            + "\"use\":\"sig\","
            + "\"alg\":\"ES256\","
            + "\"key_ops\":\"verify\""
            + "}]}";
    assertThrows(
        IOException.class,
        () -> JwkSetConverter.toKeysetHandle(jwksString, KeyAccess.publicAccess()));
  }

  @Test
  public void rsaWithoutUseAndKeyOps_toKeysetHandleSuccess() throws Exception {
    String jwksString =
        "{\"keys\":[{\"kty\":\"RSA\","
            + "\"n\":\"AM90NXQrAtt6KPSevzv9nbLJ2g_WPDH4zTwOo1slR8qC2chi6mH4TONOyAracdhQaoPwtMKge2ks"
            + "dJi1GaYwl975uvZEd9J1G078tlGrKPpy5I_OHseYDoeP8EgXawNII5ayFo-Ch_ZTxyzOuWmeb3DJft177D7T"
            + "Foz-zrMoTDGV4gwhBPeVfSk5DYvY06hF740KZq89nXBX_51KE5C-M9hBJMK9VA7BiGM8qjeu7l7ppXdzfvf6"
            + "azfkIogKMV7Xk0aw6nCW6h49BYuIu3TVjiToLEu5kX0z501whcCI8SA1tlicl7CzOCvVF70vg03RAB5vZQWY"
            + "2oFr3AwKBYDHvsc\","
            + "\"e\":\"AQAB\",\"alg\":\"RS256\"}]}";
    // ignore returned value, we only test that it worked.
    JwkSetConverter.toKeysetHandle(jwksString, KeyAccess.publicAccess());

    String psJwksString = jwksString.replace("RS256", "PS256");
    // ignore returned value, we only test that it worked.
    JwkSetConverter.toKeysetHandle(psJwksString, KeyAccess.publicAccess());
  }

  @Test
  public void rsaWithUnknownField_toKeysetHandleSuccess() throws Exception {
    String jwksString =
        "{\"keys\":[{\"kty\":\"RSA\","
            + "\"n\":\"AM90NXQrAtt6KPSevzv9nbLJ2g_WPDH4zTwOo1slR8qC2chi6mH4TONOyAracdhQaoPwtMKge2ks"
            + "dJi1GaYwl975uvZEd9J1G078tlGrKPpy5I_OHseYDoeP8EgXawNII5ayFo-Ch_ZTxyzOuWmeb3DJft177D7T"
            + "Foz-zrMoTDGV4gwhBPeVfSk5DYvY06hF740KZq89nXBX_51KE5C-M9hBJMK9VA7BiGM8qjeu7l7ppXdzfvf6"
            + "azfkIogKMV7Xk0aw6nCW6h49BYuIu3TVjiToLEu5kX0z501whcCI8SA1tlicl7CzOCvVF70vg03RAB5vZQWY"
            + "2oFr3AwKBYDHvsc\","
            + "\"unknown\":1234,"
            + "\"e\":\"AQAB\",\"use\":\"sig\",\"alg\":\"RS256\",\"key_ops\":[\"verify\"]}]}";
    // ignore returned value, we only test that it worked.
    JwkSetConverter.toKeysetHandle(jwksString, KeyAccess.publicAccess());

    String psJwksString = jwksString.replace("RS256", "PS256");
    // ignore returned value, we only test that it worked.
    JwkSetConverter.toKeysetHandle(psJwksString, KeyAccess.publicAccess());
  }

  @Test
  public void rsaPrivateKey_fails() throws Exception {
    // Example from https://datatracker.ietf.org/doc/html/rfc7517#appendix-A.2
    String jwksString =
        "{\"keys\":["
            + "{\"kty\":\"RSA\","
            + "\"n\":\"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4"
            + "cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMst"
            + "n64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2Q"
            + "vzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbIS"
            + "D08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw"
            + "0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw\","
            + "\"e\":\"AQAB\","
            + "\"d\":\"X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9"
            + "M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2vv7B6NqXSzUvxT0_YSfqij"
            + "wp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d"
            + "_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk5ZiG7xojPLu4sbg1U2jx4IBTNBz"
            + "nbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFz"
            + "me1z0HbIkfz0Y6mqnOYtqc0X4jfcKoAC8Q\","
            + "\"p\":\"83i-7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxtPV"
            + "nwD20R-60eTDmD2ujnMt5PoqMrm8RfmNhVWDtjjMmCMjOpSXicFHj7XOuVIYQyqV"
            + "WlWEh6dN36GVZYk93N8Bc9vY41xy8B9RzzOGVQzXvNEvn7O0nVbfs\","
            + "\"q\":\"3dfOR9cuYq-0S-mkFLzgItgMEfFzB2q3hWehMuG0oCuqnb3vobLyum"
            + "qjVZQO1dIrdwgTnCdpYzBcOfW5r370AFXjiWft_NGEiovonizhKpo9VVS78TzFgx"
            + "kIdrecRezsZ-1kYd_s1qDbxtkDEgfAITAG9LUnADun4vIcb6yelxk\","
            + "\"dp\":\"G4sPXkc6Ya9y8oJW9_ILj4xuppu0lzi_H7VTkS8xj5SdX3coE0oim"
            + "YwxIi2emTAue0UOa5dpgFGyBJ4c8tQ2VF402XRugKDTP8akYhFo5tAA77Qe_Nmtu"
            + "YZc3C3m3I24G2GvR5sSDxUyAN2zq8Lfn9EUms6rY3Ob8YeiKkTiBj0\","
            + "\"dq\":\"s9lAH9fggBsoFR8Oac2R_E2gw282rT2kGOAhvIllETE1efrA6huUU"
            + "vMfBcMpn8lqeW6vzznYY5SSQF7pMdC_agI3nG8Ibp1BUb0JUiraRNqUfLhcQb_d9"
            + "GF4Dh7e74WbRsobRonujTYN1xCaP6TO61jvWrX-L18txXw494Q_cgk\","
            + "\"qi\":\"GyM_p6JrXySiz1toFgKbWV-JdI3jQ4ypu9rbMWx3rQJBfmt0FoYzg"
            + "UIZEVFEcOqwemRN81zoDAaa-Bk0KWNGDjJHZDdDmFhW3AN7lI-puxk_mHZGJ11rx"
            + "yR8O55XLSe3SPmRfKwZI6yU24ZxvQKFYItdldUKGzO6Ia6zTKhAVRU\","
            + "\"alg\":\"RS256\","
            + "\"kid\":\"2011-04-29\"}]}";
    assertThrows(
        UnsupportedOperationException.class,
        () -> JwkSetConverter.toKeysetHandle(jwksString, KeyAccess.publicAccess()));

    String psJwksString = jwksString.replace("RS256", "PS256");
    assertThrows(
        UnsupportedOperationException.class,
        () -> JwkSetConverter.toKeysetHandle(psJwksString, KeyAccess.publicAccess()));
  }

  @Test
  public void rsaWithoutAlg_toKeysetHandleFails() throws Exception {
    String jwksString =
        "{\"keys\":[{\"kty\":\"RSA\","
            + "\"n\":\"AM90NXQrAtt6KPSevzv9nbLJ2g_WPDH4zTwOo1slR8qC2chi6mH4TONOyAracdhQaoPwtMKge2ks"
            + "dJi1GaYwl975uvZEd9J1G078tlGrKPpy5I_OHseYDoeP8EgXawNII5ayFo-Ch_ZTxyzOuWmeb3DJft177D7T"
            + "Foz-zrMoTDGV4gwhBPeVfSk5DYvY06hF740KZq89nXBX_51KE5C-M9hBJMK9VA7BiGM8qjeu7l7ppXdzfvf6"
            + "azfkIogKMV7Xk0aw6nCW6h49BYuIu3TVjiToLEu5kX0z501whcCI8SA1tlicl7CzOCvVF70vg03RAB5vZQWY"
            + "2oFr3AwKBYDHvsc\","
            + "\"e\":\"AQAB\",\"use\":\"sig\",\"key_ops\":[\"verify\"]}]}";
    assertThrows(
        IOException.class,
        () -> JwkSetConverter.toKeysetHandle(jwksString, KeyAccess.publicAccess()));
  }

  @Test
  public void rsaWithoutKty_toKeysetHandleFails() throws Exception {
    String jwksString =
        "{\"keys\":[{"
            + "\"n\":\"AM90NXQrAtt6KPSevzv9nbLJ2g_WPDH4zTwOo1slR8qC2chi6mH4TONOyAracdhQaoPwtMKge2ks"
            + "dJi1GaYwl975uvZEd9J1G078tlGrKPpy5I_OHseYDoeP8EgXawNII5ayFo-Ch_ZTxyzOuWmeb3DJft177D7T"
            + "Foz-zrMoTDGV4gwhBPeVfSk5DYvY06hF740KZq89nXBX_51KE5C-M9hBJMK9VA7BiGM8qjeu7l7ppXdzfvf6"
            + "azfkIogKMV7Xk0aw6nCW6h49BYuIu3TVjiToLEu5kX0z501whcCI8SA1tlicl7CzOCvVF70vg03RAB5vZQWY"
            + "2oFr3AwKBYDHvsc\","
            + "\"e\":\"AQAB\",\"use\":\"sig\",\"alg\":\"RS256\",\"key_ops\":[\"verify\"]}]}";
    assertThrows(
        IOException.class,
        () -> JwkSetConverter.toKeysetHandle(jwksString, KeyAccess.publicAccess()));

    String psJwksString = jwksString.replace("RS256", "PS256");
    assertThrows(
        IOException.class,
        () -> JwkSetConverter.toKeysetHandle(psJwksString, KeyAccess.publicAccess()));
  }

  @Test
  public void rsaWithSmallN_getPrimitiveFails() throws Exception {
    String jwksString =
        "{\"keys\":[{\"kty\":\"RSA\","
            + "\"n\":\"AAAwOQ\","
            + "\"e\":\"AQAB\",\"use\":\"sig\",\"alg\":\"RS256\",\"key_ops\":[\"verify\"]}]}";
    KeysetHandle handle = JwkSetConverter.toKeysetHandle(jwksString, KeyAccess.publicAccess());
    assertThrows(
        GeneralSecurityException.class, () -> handle.getPrimitive(JwtPublicKeyVerify.class));

    String psJwksString = jwksString.replace("RS256", "PS256");
    KeysetHandle psHandle = JwkSetConverter.toKeysetHandle(psJwksString, KeyAccess.publicAccess());
    assertThrows(
        GeneralSecurityException.class, () -> psHandle.getPrimitive(JwtPublicKeyVerify.class));
  }

  @Test
  public void rsaWithInvalidKty_toKeysetHandleFails() throws Exception {
    String jwksString =
        "{\"keys\":[{\"kty\":\"EC\","
            + "\"n\":\"AM90NXQrAtt6KPSevzv9nbLJ2g_WPDH4zTwOo1slR8qC2chi6mH4TONOyAracdhQaoPwtMKge2ks"
            + "dJi1GaYwl975uvZEd9J1G078tlGrKPpy5I_OHseYDoeP8EgXawNII5ayFo-Ch_ZTxyzOuWmeb3DJft177D7T"
            + "Foz-zrMoTDGV4gwhBPeVfSk5DYvY06hF740KZq89nXBX_51KE5C-M9hBJMK9VA7BiGM8qjeu7l7ppXdzfvf6"
            + "azfkIogKMV7Xk0aw6nCW6h49BYuIu3TVjiToLEu5kX0z501whcCI8SA1tlicl7CzOCvVF70vg03RAB5vZQWY"
            + "2oFr3AwKBYDHvsc\","
            + "\"e\":\"AQAB\",\"use\":\"sig\",\"alg\":\"RS256\",\"key_ops\":[\"verify\"]}]}";
    assertThrows(
        IOException.class,
        () -> JwkSetConverter.toKeysetHandle(jwksString, KeyAccess.publicAccess()));

    String psJwksString = jwksString.replace("RS256", "PS256");
    assertThrows(
        IOException.class,
        () -> JwkSetConverter.toKeysetHandle(psJwksString, KeyAccess.publicAccess()));
  }

  @Test
  public void rsaWithInvalidUse_toKeysetHandleFails() throws Exception {
    String jwksString =
        "{\"keys\":[{\"kty\":\"RSA\","
            + "\"n\":\"AM90NXQrAtt6KPSevzv9nbLJ2g_WPDH4zTwOo1slR8qC2chi6mH4TONOyAracdhQaoPwtMKge2ks"
            + "dJi1GaYwl975uvZEd9J1G078tlGrKPpy5I_OHseYDoeP8EgXawNII5ayFo-Ch_ZTxyzOuWmeb3DJft177D7T"
            + "Foz-zrMoTDGV4gwhBPeVfSk5DYvY06hF740KZq89nXBX_51KE5C-M9hBJMK9VA7BiGM8qjeu7l7ppXdzfvf6"
            + "azfkIogKMV7Xk0aw6nCW6h49BYuIu3TVjiToLEu5kX0z501whcCI8SA1tlicl7CzOCvVF70vg03RAB5vZQWY"
            + "2oFr3AwKBYDHvsc\","
            + "\"e\":\"AQAB\",\"use\":\"invalid\",\"alg\":\"RS256\",\"key_ops\":[\"verify\"]}]}";
    assertThrows(
        IOException.class,
        () -> JwkSetConverter.toKeysetHandle(jwksString, KeyAccess.publicAccess()));

    String psJwksString = jwksString.replace("RS256", "PS256");
    assertThrows(
        IOException.class,
        () -> JwkSetConverter.toKeysetHandle(psJwksString, KeyAccess.publicAccess()));
  }

  @Test
  public void rsaWithInvalidKeyOps_toKeysetHandleFails() throws Exception {
    String jwksString =
        "{\"keys\":[{\"kty\":\"RSA\","
            + "\"n\":\"AM90NXQrAtt6KPSevzv9nbLJ2g_WPDH4zTwOo1slR8qC2chi6mH4TONOyAracdhQaoPwtMKge2ks"
            + "dJi1GaYwl975uvZEd9J1G078tlGrKPpy5I_OHseYDoeP8EgXawNII5ayFo-Ch_ZTxyzOuWmeb3DJft177D7T"
            + "Foz-zrMoTDGV4gwhBPeVfSk5DYvY06hF740KZq89nXBX_51KE5C-M9hBJMK9VA7BiGM8qjeu7l7ppXdzfvf6"
            + "azfkIogKMV7Xk0aw6nCW6h49BYuIu3TVjiToLEu5kX0z501whcCI8SA1tlicl7CzOCvVF70vg03RAB5vZQWY"
            + "2oFr3AwKBYDHvsc\","
            + "\"e\":\"AQAB\",\"use\":\"sig\",\"alg\":\"RS256\",\"key_ops\":[\"invalid\"]}]}";
    assertThrows(
        IOException.class,
        () -> JwkSetConverter.toKeysetHandle(jwksString, KeyAccess.publicAccess()));

    String psJwksString = jwksString.replace("RS256", "PS256");
    assertThrows(
        IOException.class,
        () -> JwkSetConverter.toKeysetHandle(psJwksString, KeyAccess.publicAccess()));
  }

  @Test
  public void rsaWithStringKeyOps_toKeysetHandleFails() throws Exception {
    String jwksString =
        "{\"keys\":[{\"kty\":\"RSA\","
            + "\"n\":\"AM90NXQrAtt6KPSevzv9nbLJ2g_WPDH4zTwOo1slR8qC2chi6mH4TONOyAracdhQaoPwtMKge2ks"
            + "dJi1GaYwl975uvZEd9J1G078tlGrKPpy5I_OHseYDoeP8EgXawNII5ayFo-Ch_ZTxyzOuWmeb3DJft177D7T"
            + "Foz-zrMoTDGV4gwhBPeVfSk5DYvY06hF740KZq89nXBX_51KE5C-M9hBJMK9VA7BiGM8qjeu7l7ppXdzfvf6"
            + "azfkIogKMV7Xk0aw6nCW6h49BYuIu3TVjiToLEu5kX0z501whcCI8SA1tlicl7CzOCvVF70vg03RAB5vZQWY"
            + "2oFr3AwKBYDHvsc\","
            + "\"e\":\"AQAB\",\"use\":\"sig\",\"alg\":\"RS256\",\"key_ops\":\"verify\"}]}";
    assertThrows(
        IOException.class,
        () -> JwkSetConverter.toKeysetHandle(jwksString, KeyAccess.publicAccess()));

    String psJwksString = jwksString.replace("RS256", "PS256");
    assertThrows(
        IOException.class,
        () -> JwkSetConverter.toKeysetHandle(psJwksString, KeyAccess.publicAccess()));
  }
}
