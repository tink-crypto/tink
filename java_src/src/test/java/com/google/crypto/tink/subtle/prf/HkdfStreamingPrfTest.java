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

import com.google.crypto.tink.prf.Prf;
import com.google.crypto.tink.subtle.Enums.HashType;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.subtle.Hkdf;
import com.google.crypto.tink.subtle.Random;
import com.google.crypto.tink.testing.TestUtil;
import java.io.InputStream;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for HkdfStreamingPrf */
@RunWith(JUnit4.class)
public final class HkdfStreamingPrfTest {
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

  // https://tools.ietf.org/html/rfc5869#appendix-A.1
  @Test
  public void testComputePrf_rfc589vector1() throws Exception {
    HashType hash = HashType.SHA256;
    byte[] ikm = Hex.decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    byte[] salt = Hex.decode("000102030405060708090a0b0c");
    byte[] info = Hex.decode("f0f1f2f3f4f5f6f7f8f9");
    byte[] expectedResult =
        Hex.decode(
            "3cb25f25faacd57a90434f64d0362f2a"
                + "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
                + "34007208d5b887185865");
    HkdfStreamingPrf prf = new HkdfStreamingPrf(hash, ikm, salt);
    InputStream input = prf.computePrf(info);

    byte[] output = new byte[expectedResult.length];
    assertThat(input.read(output)).isEqualTo(expectedResult.length);
    assertThat(output).isEqualTo(expectedResult);
  }

  // https://tools.ietf.org/html/rfc5869#appendix-A.2
  @Test
  public void testComputePrf_rfc589vector2() throws Exception {
    HashType hash = HashType.SHA256;
    byte[] ikm =
        Hex.decode(
            "000102030405060708090a0b0c0d0e0f"
                + "101112131415161718191a1b1c1d1e1f"
                + "202122232425262728292a2b2c2d2e2f"
                + "303132333435363738393a3b3c3d3e3f"
                + "404142434445464748494a4b4c4d4e4f");
    byte[] salt =
        Hex.decode(
            "606162636465666768696a6b6c6d6e6f"
                + "707172737475767778797a7b7c7d7e7f"
                + "808182838485868788898a8b8c8d8e8f"
                + "909192939495969798999a9b9c9d9e9f"
                + "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf");
    byte[] info =
        Hex.decode(
            "b0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
                + "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf"
                + "d0d1d2d3d4d5d6d7d8d9dadbdcdddedf"
                + "e0e1e2e3e4e5e6e7e8e9eaebecedeeef"
                + "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
    byte[] expectedResult =
        Hex.decode(
            "b11e398dc80327a1c8e7f78c596a4934"
                + "4f012eda2d4efad8a050cc4c19afa97c"
                + "59045a99cac7827271cb41c65e590e09"
                + "da3275600c2f09b8367793a9aca3db71"
                + "cc30c58179ec3e87c14c01d5c1f3434f"
                + "1d87");
    HkdfStreamingPrf prf = new HkdfStreamingPrf(hash, ikm, salt);
    InputStream input = prf.computePrf(info);

    byte[] output = new byte[expectedResult.length];
    assertThat(input.read(output)).isEqualTo(expectedResult.length);
    assertThat(output).isEqualTo(expectedResult);
  }

  // https://tools.ietf.org/html/rfc5869#appendix-A.3
  @Test
  public void testComputePrf_rfc589vector3() throws Exception {
    HashType hash = HashType.SHA256;
    byte[] ikm = Hex.decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    byte[] salt = Hex.decode("");
    byte[] info = Hex.decode("");
    byte[] expectedResult =
        Hex.decode(
            "8da4e775a563c18f715f802a063c5a31"
                + "b8a11f5c5ee1879ec3454e5f3c738d2d"
                + "9d201395faa4b61a96c8");
    HkdfStreamingPrf prf = new HkdfStreamingPrf(hash, ikm, salt);
    InputStream input = prf.computePrf(info);

    byte[] output = new byte[expectedResult.length];
    assertThat(input.read(output)).isEqualTo(expectedResult.length);
    assertThat(output).isEqualTo(expectedResult);
  }

  // https://tools.ietf.org/html/rfc5869#appendix-A.4
  @Test
  public void testComputePrf_rfc589vector4() throws Exception {
    HashType hash = HashType.SHA1;
    byte[] ikm = Hex.decode("0b0b0b0b0b0b0b0b0b0b0b");
    byte[] salt = Hex.decode("000102030405060708090a0b0c");
    byte[] info = Hex.decode("f0f1f2f3f4f5f6f7f8f9");
    byte[] expectedResult =
        Hex.decode(
            "085a01ea1b10f36933068b56efa5ad81"
                + "a4f14b822f5b091568a9cdd4f155fda2"
                + "c22e422478d305f3f896");
    HkdfStreamingPrf prf = new HkdfStreamingPrf(hash, ikm, salt);
    InputStream input = prf.computePrf(info);

    byte[] output = new byte[expectedResult.length];
    assertThat(input.read(output)).isEqualTo(expectedResult.length);
    assertThat(output).isEqualTo(expectedResult);
  }

  // https://tools.ietf.org/html/rfc5869#appendix-A.5
  @Test
  public void testComputePrf_rfc589vector5() throws Exception {
    HashType hash = HashType.SHA1;
    byte[] ikm =
        Hex.decode(
            "000102030405060708090a0b0c0d0e0f"
                + "101112131415161718191a1b1c1d1e1f"
                + "202122232425262728292a2b2c2d2e2f"
                + "303132333435363738393a3b3c3d3e3f"
                + "404142434445464748494a4b4c4d4e4f");
    byte[] salt =
        Hex.decode(
            "606162636465666768696a6b6c6d6e6f"
                + "707172737475767778797a7b7c7d7e7f"
                + "808182838485868788898a8b8c8d8e8f"
                + "909192939495969798999a9b9c9d9e9f"
                + "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf");
    byte[] info =
        Hex.decode(
            "b0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
                + "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf"
                + "d0d1d2d3d4d5d6d7d8d9dadbdcdddedf"
                + "e0e1e2e3e4e5e6e7e8e9eaebecedeeef"
                + "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
    byte[] expectedResult =
        Hex.decode(
            "0bd770a74d1160f7c9f12cd5912a06eb"
                + "ff6adcae899d92191fe4305673ba2ffe"
                + "8fa3f1a4e5ad79f3f334b3b202b2173c"
                + "486ea37ce3d397ed034c7f9dfeb15c5e"
                + "927336d0441f4c4300e2cff0d0900b52"
                + "d3b4");
    HkdfStreamingPrf prf = new HkdfStreamingPrf(hash, ikm, salt);
    InputStream input = prf.computePrf(info);

    byte[] output = new byte[expectedResult.length];
    assertThat(input.read(output)).isEqualTo(expectedResult.length);
    assertThat(output).isEqualTo(expectedResult);
  }

  // https://tools.ietf.org/html/rfc5869#appendix-A.6
  @Test
  public void testComputePrf_rfc589vector6() throws Exception {
    HashType hash = HashType.SHA1;
    byte[] ikm = Hex.decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    byte[] salt = Hex.decode("");
    byte[] info = Hex.decode("");
    byte[] expectedResult =
        Hex.decode(
            "0ac1af7002b3d761d1e55298da9d0506"
                + "b9ae52057220a306e07b6b87e8df21d0"
                + "ea00033de03984d34918");
    HkdfStreamingPrf prf = new HkdfStreamingPrf(hash, ikm, salt);
    InputStream input = prf.computePrf(info);

    byte[] output = new byte[expectedResult.length];
    assertThat(input.read(output)).isEqualTo(expectedResult.length);
    assertThat(output).isEqualTo(expectedResult);
  }

  // https://tools.ietf.org/html/rfc5869#appendix-A.7
  @Test
  public void testComputePrf_rfc589vector7() throws Exception {
    HashType hash = HashType.SHA1;
    byte[] ikm = Hex.decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    // Since HMAC anyhow pads, this is the same as an absent salt.
    byte[] salt = Hex.decode("");
    byte[] info = Hex.decode("");
    byte[] expectedResult =
        Hex.decode(
            "0ac1af7002b3d761d1e55298da9d0506"
                + "b9ae52057220a306e07b6b87e8df21d0"
                + "ea00033de03984d34918");
    HkdfStreamingPrf prf = new HkdfStreamingPrf(hash, ikm, salt);
    InputStream input = prf.computePrf(info);

    byte[] output = new byte[expectedResult.length];
    assertThat(input.read(output)).isEqualTo(expectedResult.length);
    assertThat(output).isEqualTo(expectedResult);
  }

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
}
