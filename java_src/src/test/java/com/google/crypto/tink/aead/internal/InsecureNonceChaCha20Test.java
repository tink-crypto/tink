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

package com.google.crypto.tink.aead.internal;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertThrows;

import com.google.common.truth.Truth;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.subtle.Random;
import com.google.crypto.tink.testing.TestUtil;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for {@link InsecureNonceChaCha20}. */
@RunWith(JUnit4.class)
public class InsecureNonceChaCha20Test {
  public InsecureNonceChaCha20 createInstance(final byte[] key) throws InvalidKeyException {
    return new InsecureNonceChaCha20(key, /*initialCounter=*/ 0);
  }

  @Test
  public void testEncryptDecrypt() throws Exception {
    for (int i = 0; i < 64; i++) {
      byte[] key = Random.randBytes(32);
      InsecureNonceChaCha20 cipher = createInstance(key);
      for (int j = 0; j < 64; j++) {
        byte[] expectedInput = Random.randBytes(new java.util.Random().nextInt(300));
        byte[] nonce = Random.randBytes(12);
        byte[] output = cipher.encrypt(nonce, expectedInput);
        byte[] actualInput = cipher.decrypt(nonce, output);
        assertArrayEquals(
            String.format(
                "\n\nMessage: %s\nKey: %s\nOutput: %s\nDecrypted Msg: %s\n",
                TestUtil.hexEncode(expectedInput),
                TestUtil.hexEncode(key),
                TestUtil.hexEncode(output),
                TestUtil.hexEncode(actualInput)),
            expectedInput,
            actualInput);
      }
    }
  }

  @Test
  public void testNewCipherThrowsIllegalArgExpWhenKeyLenIsLessThan32() throws Exception {
    InvalidKeyException e =
        assertThrows(InvalidKeyException.class, () -> createInstance(new byte[1]));
    assertThat(e).hasMessageThat().containsMatch("The key length in bytes must be 32.");
  }

  @Test
  public void testNewCipherThrowsIllegalArgExpWhenKeyLenIsGreaterThan32() throws Exception {
    InvalidKeyException e =
        assertThrows(InvalidKeyException.class, () -> createInstance(new byte[33]));
    assertThat(e).hasMessageThat().containsMatch("The key length in bytes must be 32.");
  }

  @Test
  public void testEncryptDecryptThrowsGeneralSecurityExpWithInvalidNonceSize() throws Exception {
    InsecureNonceChaCha20 cipher = createInstance(Random.randBytes(32));
    byte[] nonce = Random.randBytes(13);
    byte[] input = Random.randBytes(16);
    GeneralSecurityException e =
        assertThrows(GeneralSecurityException.class, () -> cipher.encrypt(nonce, input));
    assertThat(e)
        .hasMessageThat()
        .contains("The nonce length (in bytes) must be 12");
    e = assertThrows(GeneralSecurityException.class, () -> cipher.decrypt(nonce, input));
    assertThat(e)
        .hasMessageThat()
        .contains("The nonce length (in bytes) must be 12");
  }

  /** https://tools.ietf.org/html/rfc7539#section-2.4.2 */
  private static class Rfc7539TestVector {
    public byte[] key;
    public byte[] plaintext;
    public byte[] nonce;
    public byte[] ciphertext;
    int initialCounter;

    public Rfc7539TestVector(
        String key, String plaintext, String nonce, String ciphertext, int initialCounter) {
      this.key = Hex.decode(key);
      this.plaintext = Hex.decode(plaintext);
      this.nonce = Hex.decode(nonce);
      this.ciphertext = Hex.decode(ciphertext);
      this.initialCounter = initialCounter;
    }
  }

  final Rfc7539TestVector[] rfc7539TestVectors = {
    new Rfc7539TestVector(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a20496620"
            + "4920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f722074686520667574"
            + "7572652c2073756e73637265656e20776f756c642062652069742e",
        "000000000000004a00000000",
        "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0bf91b65c5524733ab8f593dabcd"
            + "62b3571639d624e65152ab8f530c359f0861d807ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf8"
            + "06818ce91ab77937365af90bbf74a35be6b40b8eedf2785e42874d",
        1),
    new Rfc7539TestVector(
        "0000000000000000000000000000000000000000000000000000000000000000",
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            + "00000000000000000000000000000000000000",
        "000000000000000000000000",
        "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7da41597c5157488d7724e03fb8"
            + "d84a376a43b8f41518a11cc387b669b2ee6586",
        0),
    new Rfc7539TestVector(
        "0000000000000000000000000000000000000000000000000000000000000001",
        "416e79207375626d697373696f6e20746f20746865204945544620696e74656e6465642062792074686520436f"
            + "6e7472696275746f7220666f72207075626c69636174696f6e20617320616c6c206f722070617274206f"
            + "6620616e204945544620496e7465726e65742d4472616674206f722052464320616e6420616e79207374"
            + "6174656d656e74206d6164652077697468696e2074686520636f6e74657874206f6620616e2049455446"
            + "20616374697669747920697320636f6e7369646572656420616e20224945544620436f6e747269627574"
            + "696f6e222e20537563682073746174656d656e747320696e636c756465206f72616c2073746174656d65"
            + "6e747320696e20494554462073657373696f6e732c2061732077656c6c206173207772697474656e2061"
            + "6e6420656c656374726f6e696320636f6d6d756e69636174696f6e73206d61646520617420616e792074"
            + "696d65206f7220706c6163652c207768696368206172652061646472657373656420746f",
        "000000000000000000000002",
        "a3fbf07df3fa2fde4f376ca23e82737041605d9f4f4f57bd8cff2c1d4b7955ec2a97948bd3722915c8f3d337f7"
            + "d370050e9e96d647b7c39f56e031ca5eb6250d4042e02785ececfa4b4bb5e8ead0440e20b6e8db09d881"
            + "a7c6132f420e52795042bdfa7773d8a9051447b3291ce1411c680465552aa6c405b7764d5e87bea85ad0"
            + "0f8449ed8f72d0d662ab052691ca66424bc86d2df80ea41f43abf937d3259dc4b2d0dfb48a6c9139ddd7"
            + "f76966e928e635553ba76c5c879d7b35d49eb2e62b0871cdac638939e25e8a1e0ef9d5280fa8ca328b35"
            + "1c3c765989cbcf3daa8b6ccc3aaf9f3979c92b3720fc88dc95ed84a1be059c6499b9fda236e7e818b04b"
            + "0bc39c1e876b193bfe5569753f88128cc08aaa9b63d1a16f80ef2554d7189c411f5869ca52c5b83fa36f"
            + "f216b9c1d30062bebcfd2dc5bce0911934fda79a86f6e698ced759c3ff9b6477338f3da4f9cd8514ea99"
            + "82ccafb341b2384dd902f3d1ab7ac61dd29c6f21ba5b862f3730e37cfdc4fd806c22f221",
        1),
    new Rfc7539TestVector(
        "1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0",
        "2754776173206272696c6c69672c20616e642074686520736c6974687920746f7665730a446964206779726520"
            + "616e642067696d626c6520696e2074686520776162653a0a416c6c206d696d73792077657265207468652062"
            + "6f726f676f7665732c0a416e6420746865206d6f6d65207261746873206f757467726162652e",
        "000000000000000000000002",
        "62e6347f95ed87a45ffae7426f27a1df5fb69110044c0d73118effa95b01e5cf166d3df2d721caf9b21e5fb14c"
            + "616871fd84c54f9d65b283196c7fe4f60553ebf39c6402c42234e32a356b3e764312a61a5532055716ea"
            + "d6962568f87d3f3f7704c6a8d1bcd1bf4d50d6154b6da731b187b58dfd728afa36757a797ac188d1",
        42),
    // Tests against the test vectors in Section 2.6.2 of RFC 7539.
    // https://tools.ietf.org/html/rfc7539#section-2.6.2
    new Rfc7539TestVector(
        "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "000000000001020304050607",
        "8ad5a08b905f81cc815040274ab29471a833b637e3fd0da508dbb8e2fdd1a646",
        0),
    new Rfc7539TestVector(
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "000000000000000000000000",
        "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7",
        0),
    new Rfc7539TestVector(
        "0000000000000000000000000000000000000000000000000000000000000001",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "000000000000000000000002",
        "ecfa254f845f647473d3cb140da9e87606cb33066c447b87bc2666dde3fbb739",
        0),
    new Rfc7539TestVector(
        "1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "000000000000000000000002",
        "965e3bc6f9ec7ed9560808f4d229f94b137ff275ca9b3fcbdd59deaad23310ae",
        0),
  };

  @Test
  public void testWithRfc7539TestVectors() throws Exception {
    for (Rfc7539TestVector test : rfc7539TestVectors) {
      InsecureNonceChaCha20 cipher = new InsecureNonceChaCha20(test.key, test.initialCounter);
      byte[] out = cipher.decrypt(test.nonce, test.ciphertext);
      Truth.assertThat(out).isEqualTo(test.plaintext);
    }
  }
}
