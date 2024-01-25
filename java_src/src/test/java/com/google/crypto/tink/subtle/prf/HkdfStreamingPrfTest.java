// Copyright 2020 Google LLC
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
package com.google.crypto.tink.subtle.prf;

import static com.google.common.truth.Truth.assertThat;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assume.assumeTrue;

import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.internal.EnumTypeProtoConverter;
import com.google.crypto.tink.prf.HkdfPrfKey;
import com.google.crypto.tink.prf.HkdfPrfParameters;
import com.google.crypto.tink.prf.Prf;
import com.google.crypto.tink.subtle.Enums;
import com.google.crypto.tink.subtle.Enums.HashType;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.subtle.Hkdf;
import com.google.crypto.tink.subtle.Random;
import com.google.crypto.tink.testing.TestUtil;
import com.google.crypto.tink.util.Bytes;
import com.google.crypto.tink.util.SecretBytes;
import java.io.InputStream;
import org.junit.Test;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

/** Tests for HkdfStreamingPrf */
@RunWith(Theories.class)
public final class HkdfStreamingPrfTest {

  private static final class HkdfTestVector {
    final HashType hashType;
    // "input key material" from rfc5869.
    final byte[] ikm;
    final byte[] salt;
    final byte[] info;
    final byte[] expectedResult;

    HkdfTestVector(HashType hashType, String ikm, String salt, String info, String expectedResult) {
      this.hashType = hashType;
      this.ikm = Hex.decode(ikm);
      this.salt = Hex.decode(salt);
      this.info = Hex.decode(info);
      this.expectedResult = Hex.decode(expectedResult);
    }
  }

  @DataPoints("rfcTestVectors")
  public static final HkdfTestVector[] HKDF_RFC_TEST_VECTORS =
      new HkdfTestVector[] {
        // https://tools.ietf.org/html/rfc5869#appendix-A.1
        new HkdfTestVector(
            HashType.SHA256,
            "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
            "000102030405060708090a0b0c",
            "f0f1f2f3f4f5f6f7f8f9",
            "3cb25f25faacd57a90434f64d0362f2a"
                + "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
                + "34007208d5b887185865"),
        // https://tools.ietf.org/html/rfc5869#appendix-A.2
        new HkdfTestVector(
            HashType.SHA256,
            "000102030405060708090a0b0c0d0e0f"
                + "101112131415161718191a1b1c1d1e1f"
                + "202122232425262728292a2b2c2d2e2f"
                + "303132333435363738393a3b3c3d3e3f"
                + "404142434445464748494a4b4c4d4e4f",
            "606162636465666768696a6b6c6d6e6f"
                + "707172737475767778797a7b7c7d7e7f"
                + "808182838485868788898a8b8c8d8e8f"
                + "909192939495969798999a9b9c9d9e9f"
                + "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
            "b0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
                + "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf"
                + "d0d1d2d3d4d5d6d7d8d9dadbdcdddedf"
                + "e0e1e2e3e4e5e6e7e8e9eaebecedeeef"
                + "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
            "b11e398dc80327a1c8e7f78c596a4934"
                + "4f012eda2d4efad8a050cc4c19afa97c"
                + "59045a99cac7827271cb41c65e590e09"
                + "da3275600c2f09b8367793a9aca3db71"
                + "cc30c58179ec3e87c14c01d5c1f3434f"
                + "1d87"),
        // https://tools.ietf.org/html/rfc5869#appendix-A.3
        new HkdfTestVector(
            HashType.SHA256,
            "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
            "",
            "",
            "8da4e775a563c18f715f802a063c5a31"
                + "b8a11f5c5ee1879ec3454e5f3c738d2d"
                + "9d201395faa4b61a96c8"),
        // https://tools.ietf.org/html/rfc5869#appendix-A.4
        new HkdfTestVector(
            HashType.SHA1,
            "0b0b0b0b0b0b0b0b0b0b0b",
            "000102030405060708090a0b0c",
            "f0f1f2f3f4f5f6f7f8f9",
            "085a01ea1b10f36933068b56efa5ad81"
                + "a4f14b822f5b091568a9cdd4f155fda2"
                + "c22e422478d305f3f896"),
        // https://tools.ietf.org/html/rfc5869#appendix-A.5
        new HkdfTestVector(
            HashType.SHA1,
            "000102030405060708090a0b0c0d0e0f"
                + "101112131415161718191a1b1c1d1e1f"
                + "202122232425262728292a2b2c2d2e2f"
                + "303132333435363738393a3b3c3d3e3f"
                + "404142434445464748494a4b4c4d4e4f",
            "606162636465666768696a6b6c6d6e6f"
                + "707172737475767778797a7b7c7d7e7f"
                + "808182838485868788898a8b8c8d8e8f"
                + "909192939495969798999a9b9c9d9e9f"
                + "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
            "b0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
                + "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf"
                + "d0d1d2d3d4d5d6d7d8d9dadbdcdddedf"
                + "e0e1e2e3e4e5e6e7e8e9eaebecedeeef"
                + "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
            "0bd770a74d1160f7c9f12cd5912a06eb"
                + "ff6adcae899d92191fe4305673ba2ffe"
                + "8fa3f1a4e5ad79f3f334b3b202b2173c"
                + "486ea37ce3d397ed034c7f9dfeb15c5e"
                + "927336d0441f4c4300e2cff0d0900b52"
                + "d3b4"),
        // https://tools.ietf.org/html/rfc5869#appendix-A.6
        new HkdfTestVector(
            HashType.SHA1,
            "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
            "",
            "",
            "0ac1af7002b3d761d1e55298da9d0506"
                + "b9ae52057220a306e07b6b87e8df21d0"
                + "ea00033de03984d34918"),
        // https://tools.ietf.org/html/rfc5869#appendix-A.7
        new HkdfTestVector(
            HashType.SHA1,
            "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c",
            "",
            "",
            "2c91117204d745f3500d636a62f64f0a"
                + "b3bae548aa53d423b0d1f27ebba6f5e5"
                + "673a081d70cce7acfc48")
      };

  // This converter is not used with a proto but rather with an ordinary enum type.
  private static final EnumTypeProtoConverter<HashType, HkdfPrfParameters.HashType>
      HASH_TYPE_CONVERTER =
          EnumTypeProtoConverter.<Enums.HashType, HkdfPrfParameters.HashType>builder()
              .add(Enums.HashType.SHA1, HkdfPrfParameters.HashType.SHA1)
              .add(Enums.HashType.SHA224, HkdfPrfParameters.HashType.SHA224)
              .add(Enums.HashType.SHA256, HkdfPrfParameters.HashType.SHA256)
              .add(Enums.HashType.SHA384, HkdfPrfParameters.HashType.SHA384)
              .add(Enums.HashType.SHA512, HkdfPrfParameters.HashType.SHA512)
              .build();

  // GENERIC TESTS ===============================================================
  // These can be used for any streaming prf which generates enough output.
  @Test
  public void testComputePrf_basic() throws Exception {
    HkdfStreamingPrf prf =
        new HkdfStreamingPrf(HashType.SHA1, "key0123456".getBytes(UTF_8), "salt".getBytes(UTF_8));
    InputStream input = prf.computePrf("input".getBytes(UTF_8));
    byte[] output = new byte[10];
    assertThat(input.read(output)).isEqualTo(10);
  }

  @Test
  public void testComputePrf_differentInputDifferentValues() throws Exception {
    HkdfStreamingPrf prf =
        new HkdfStreamingPrf(HashType.SHA1, "key0123456".getBytes(UTF_8), "salt".getBytes(UTF_8));
    InputStream input = prf.computePrf("input".getBytes(UTF_8));
    byte[] output = new byte[10];
    assertThat(input.read(output)).isEqualTo(10);

    InputStream input2 = prf.computePrf("input2".getBytes(UTF_8));
    byte[] output2 = new byte[10];
    assertThat(input2.read(output2)).isEqualTo(10);
    assertThat(output).isNotEqualTo(output2);
  }

  @Test
  public void testComputePrf_sameInputSameValue() throws Exception {
    HkdfStreamingPrf prf =
        new HkdfStreamingPrf(HashType.SHA1, "key0123456".getBytes(UTF_8), "salt".getBytes(UTF_8));
    InputStream input = prf.computePrf("input".getBytes(UTF_8));
    byte[] output = new byte[10];
    assertThat(input.read(output)).isEqualTo(10);

    InputStream input2 = prf.computePrf("input".getBytes(UTF_8));
    byte[] output2 = new byte[10];
    assertThat(input2.read(output2)).isEqualTo(10);
    assertThat(output).isEqualTo(output2);
  }

  @Test
  public void testComputePrf_sameInputDifferentInterfacesSameValue() throws Exception {
    HkdfStreamingPrf prf =
        new HkdfStreamingPrf(HashType.SHA1, "key0123456".getBytes(UTF_8), "salt".getBytes(UTF_8));
    InputStream input = prf.computePrf("input".getBytes(UTF_8));
    byte[] output = new byte[100];
    assertThat(input.read(output)).isEqualTo(100);

    // Use the other interface to read the input.
    InputStream input2 = prf.computePrf("input".getBytes(UTF_8));
    byte[] output2 = new byte[100];
    output2[0] = (byte) input2.read();
    output2[1] = (byte) input2.read();
    assertThat(input2.read(output2, 2, 33)).isEqualTo(33);
    output2[35] = (byte) input2.read();
    assertThat(input2.read(output2, 36, 64)).isEqualTo(64);
    assertThat(output).isEqualTo(output2);
  }

  @Test
  public void testComputePrf_exhaustStream() throws Exception {
    HkdfStreamingPrf prf =
        new HkdfStreamingPrf(HashType.SHA512, "key0123456".getBytes(UTF_8), "salt".getBytes(UTF_8));
    InputStream input = prf.computePrf("input".getBytes(UTF_8));
    final int maxOutputLength = 255 * (512 / 8);
    byte[] output = new byte[maxOutputLength + 50];
    assertThat(input.read(output)).isEqualTo(maxOutputLength);
  }

  // CORRECTNESS TESTS ===============================================================
  // RFC test vectors.
  @Theory
  public void testComputePrf_rfc5869testVectors(@FromDataPoints("rfcTestVectors") HkdfTestVector t)
      throws Exception {
    HkdfStreamingPrf prf = new HkdfStreamingPrf(t.hashType, t.ikm, t.salt);
    byte[] output = new byte[t.expectedResult.length];

    InputStream input = prf.computePrf(t.info);

    assertThat(input.read(output)).isEqualTo(t.expectedResult.length);
    assertThat(output).isEqualTo(t.expectedResult);
  }

  // OTHER TESTS ===============================================================
  @Test
  public void testComputePrf_compareToHkdfUtil() throws Exception {
    HashType hash = HashType.SHA1;
    byte[] ikm = Random.randBytes(123);
    byte[] salt = Random.randBytes(234);
    byte[] info = Random.randBytes(345);
    byte[] result = new byte[456];

    HkdfStreamingPrf prf = new HkdfStreamingPrf(hash, ikm, salt);
    InputStream input = prf.computePrf(info);
    input.read(result);

    assertThat(Hkdf.computeHkdf("HmacSha1", ikm, salt, info, result.length)).isEqualTo(result);
  }

  @Test
  public void testComputePrf_compareToHkdfUtilSha384() throws Exception {
    HashType hash = HashType.SHA384;
    byte[] ikm = Random.randBytes(123);
    byte[] salt = Random.randBytes(234);
    byte[] info = Random.randBytes(345);
    byte[] result = new byte[456];

    HkdfStreamingPrf prf = new HkdfStreamingPrf(hash, ikm, salt);
    InputStream input = prf.computePrf(info);
    input.read(result);

    assertThat(Hkdf.computeHkdf("HmacSha384", ikm, salt, info, result.length)).isEqualTo(result);
  }

  @Test
  public void testPrfUniformity() throws Exception {
    for (int i = 0; i < HashType.values().length; i++) {
      byte[] ikm = Random.randBytes(128);
      byte[] salt = Random.randBytes(128);
      byte[] message = Random.randBytes(1024);
      Prf prf = PrfImpl.wrap(new HkdfStreamingPrf(HashType.SHA256, ikm, salt));
      byte[] prBytes = prf.compute(message, message.length);
      TestUtil.ztestUniformString(prBytes);
      TestUtil.ztestAutocorrelationUniformString(prBytes);
      TestUtil.ztestCrossCorrelationUniformStrings(prBytes, message);
    }
  }

  @Test
  public void create_works() throws Exception {
    HkdfPrfKey key =
        HkdfPrfKey.builder()
            .setParameters(
                HkdfPrfParameters.builder()
                    .setHashType(HkdfPrfParameters.HashType.SHA256)
                    .setKeySizeBytes(32)
                    .setSalt(Bytes.copyFrom(Random.randBytes(5)))
                    .build())
            .setKeyBytes(SecretBytes.copyFrom(Random.randBytes(32), InsecureSecretKeyAccess.get()))
            .build();

    StreamingPrf streamingPrf = HkdfStreamingPrf.create(key);

    assertThat(streamingPrf).isNotNull();
  }

  @Theory
  public void create_isCorrect(@FromDataPoints("rfcTestVectors") HkdfTestVector t)
      throws Exception {
    assumeTrue(t.ikm.length >= 16);

    HkdfPrfKey key =
        HkdfPrfKey.builder()
            .setParameters(
                HkdfPrfParameters.builder()
                    .setHashType(HASH_TYPE_CONVERTER.fromProtoEnum(t.hashType))
                    .setKeySizeBytes(t.ikm.length)
                    .setSalt(Bytes.copyFrom(t.salt))
                    .build())
            .setKeyBytes(SecretBytes.copyFrom(t.ikm, InsecureSecretKeyAccess.get()))
            .build();
    StreamingPrf streamingPrf = HkdfStreamingPrf.create(key);
    byte[] result = new byte[t.expectedResult.length];

    assertThat(streamingPrf.computePrf(t.info).read(result)).isEqualTo(t.expectedResult.length);
    assertThat(result).isEqualTo(t.expectedResult);
  }
}
