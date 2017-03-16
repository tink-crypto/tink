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

package com.google.cloud.crypto.tink.subtle;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import com.google.cloud.crypto.tink.TestUtil;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.concurrent.ExecutionException;
import javax.crypto.AEADBadTagException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Unit tests for AesEax
 * TODO(bleichen): Add more tests:
 *   - maybe add NIST style verification.
 *   - more tests for asynchronous encryption.
 *   - tests with long ciphertexts (e.g. BC had a bug with messages of size 8k or longer)
 *   - check that IVs are distinct.
 */
@RunWith(JUnit4.class)
public class AesEaxJceTest {
  private static final int KEY_SIZE = 16;
  private static final int IV_SIZE = 16;

  /**
   * EaxTestVector
   */
  public static class EaxTestVector {
    final byte[] pt;
    final byte[] aad;
    final byte[] ct;  // nonce + ciphertext
    final String ptHex;
    final String ctHex;
    final byte[] key;
    final int ivSizeInBytes;

    public EaxTestVector(
        String message, String keyMaterial, String nonce, String aad, String ciphertext) {
      this.ptHex = message;
      this.pt = TestUtil.hexDecode(message);
      this.aad = TestUtil.hexDecode(aad);
      this.ctHex = nonce + ciphertext;
      this.ct = TestUtil.hexDecode(this.ctHex);
      this.key = TestUtil.hexDecode(keyMaterial);
      this.ivSizeInBytes = nonce.length() / 2;
    }
  };

  /**
   * Test vectors from Wycheproof.
   * TODO(bleichen): There are no 12 byte nonces here.
   */
  private static final EaxTestVector[] EAX_TEST_VECTOR = {
    new EaxTestVector(
        "",
        "010511c5e24ee7097dca93272ebfae9e",
        "93ad516bc6f7302b8edb884ca37f2e65",
        "",
        "12edfdb379ef62e845da3d17995b4a1e"),
    new EaxTestVector(
        "",
        "acf877a5aa71e794efd6dc82d5b1a155",
        "4e301710ae15b2f0ee6335d774741f7e",
        "c0e0f00a919b7652",
        "eb3dae1fc33be95848da9fd24e7dbae3"),
    new EaxTestVector(
        "c3",
        "95d8e3675bbc3b96befdc5efb7433a68",
        "0d40fdefd9289e3a49114454b3c4a5f4",
        "f2",
        "c5814dfc2f4ee1719bd5f1d5a649174c1a"),
    new EaxTestVector(
        "5810842d",
        "2eed51af91b178b26e9b53c8877a7af6",
        "e78747ca46cb9f2068e07717d5226e8a",
        "",
        "24245c5bb54aa8bfaceca3665867fa2d7de1653d"),
    new EaxTestVector(
        "5ae11bb3b7d60e55",
        "cb782da180e97023530d1612e2287f0d",
        "ba641ebe03057b387dd3132e0c7a3853",
        "",
        "f6f64fa858708b8f445812fd75a9639f635045fd5972b820"),
    new EaxTestVector(
        "54332ed26cd966761710ea58a8f248",
        "8b4457d52e5c04b38d306f8f38480e97",
        "3f9d6faca5dd97eb1bc74e1954304cca",
        "",
        "3ebbf1fe11e2f454e0ef587fb42a7588e1e32ea788cae20d1700584f448814"),
    new EaxTestVector(
        "82ce1f2934dcafe9dee7e0e7cbfdfcd0",
        "2892cf62d2cc0e8e9c796624e05920f5",
        "8a0da6d1c4b7a4f426ad62f6829cc310",
        "c3ed66484eb367c8",
        "c374afaa42d9497326af332f42d2dee8fb478c82a2b2567b0ab9597c93f137cf"),
    new EaxTestVector(
        "e0c993ff5d1d00b4cbee523a1df01db011794d54ab7a504c",
        "463d89aadfa7d8158dcff9b9c3fc32aa",
        "356ab4709b32fc85ff82f40561e9f08b",
        "5ab01a3bfa141f8d33720bd1",
        "d34bc706a9d7a2be6c2d8805cec2fac270ec6d17844b0911accb612cbb3b373438c74c1280445359"),
    new EaxTestVector(
        "e9dfb2897e44236880baf166fa62fa5b8a4713aa981dbc3fe6cf65d9f0c30f47",
        "54617abbeb90fff7095b26af0e596064",
        "2621c97c4fe379d9d42f04c479ae1bac",
        "b6b29c2fbe29dcd2",
        "212263116062443db28d6abd2c3bca880ea4d178282247fffbc10532d40e9cea"
            + "6f580fdaca33d446dd6f38a4425be844"),
    new EaxTestVector(
        "7537f3e4cbe228468a7837c66aec8a9b6033cba4f1b3d8",
        "7c74da83b1f292b869c891c80850e85f8237412e13a0bf3f",
        "cfab2c573a0e723613e6e5b58787af60",
        "",
        "98a55f7db58fde8ed8bc00c01c97a6e5bda137b03e56e0dddfbe396c44a14646cbc89979f38736"),
    // Some test vectors for counter overflow:
    // Initial counter value == 2^128-1
    new EaxTestVector(
        "0000000000000000000000000000000011111111111111111111111111111111",
        "000102030405060708090a0b0c0d0e0f",
        "3c8cc2970a008f75cc5beae2847258c2",
        "",
        "3c441f32ce07822364d7a2990e50bb13d7b02a26969e4a937e5e9073b0d9c968"
            + "db90bdb3da3d00afd0fc6a83551da95e"),
    // counter value overflows at 64-bit boundary
    new EaxTestVector(
        "0000000000000000000000000000000011111111111111111111111111111111",
        "000102030405060708090a0b0c0d0e0f",
        "aef03d00598494e9fb03cd7d8b590866",
        "",
        "d19ac59849026a91aa1b9aec29b11a202a4d739fd86c28e3ae3d588ea21d70c6"
            + "c30f6cd9202074ed6e2a2a360eac8c47"),
    // no counter overflow, but the 64 most significant bits are set.
    new EaxTestVector(
        "0000000000000000000000000000000011111111111111111111111111111111",
        "000102030405060708090a0b0c0d0e0f",
        "55d12511c696a80d0514d1ffba49cada",
        "",
        "2108558ac4b2c2d5cc66cea51d6210e046177a67631cd2dd8f09469733acb517"
            + "fc355e87a267be3ae3e44c0bf3f99b2b"),
    // counter value overflows at 32-bit boundary
    new EaxTestVector(
        "0000000000000000000000000000000011111111111111111111111111111111",
        "000102030405060708090a0b0c0d0e0f",
        "79422ddd91c4eee2deaef1f968305304",
        "",
        "4d2c1524ca4baa4eefcce6b91b227ee83abaff8105dcafa2ab191f5df2575035"
            + "e2c865ce2d7abdac024c6f991a848390"),
    // no counter overflow, but bits 32-64 and 96-128 are set.
    new EaxTestVector(
        "0000000000000000000000000000000011111111111111111111111111111111",
        "000102030405060708090a0b0c0d0e0f",
        "0af5aa7a7676e28306306bcd9bf2003a",
        "",
        "8eb01e62185d782eb9287a341a6862ac5257d6f9adc99ee0a24d9c22b3e9b38a"
            + "39c339bc8a74c75e2c65c6119544d61e"),
    // no counter overflow, lower 64 bits are 2^63-1
    new EaxTestVector(
        "0000000000000000000000000000000011111111111111111111111111111111",
        "000102030405060708090a0b0c0d0e0f",
        "af5a03ae7edd73471bdcdfac5e194a60",
        "",
        "94c5d2aca6dbbce8c24513a25e095c0e54a942860d327a222a815cc713b163b4"
            + "f50b30304e45c9d411e8df4508a98612"),
    // counter overflow between block 2 and block 3.
    new EaxTestVector(
        "0000000000000000000000000000000011111111111111111111111111111111"
            + "2222222222222222222222222222222233333333333333333333333333333333",
        "000102030405060708090a0b0c0d0e0f",
        "b37087680f0edd5a52228b8c7aaea664",
        "",
        "3bb6173e3772d4b62eef37f9ef0781f360b6c74be3bf6b371067bc1b090d9d66"
            + "22a1fbec6ac471b3349cd4277a101d40890fbf27dfdcd0b4e3781f9806daabb6"
            + "a0498745e59999ddc32d5b140241124e"),
    // no counter overflow, the lower 64 bits are 2^63-4.
    new EaxTestVector(
        "0000000000000000000000000000000011111111111111111111111111111111"
            + "2222222222222222222222222222222233333333333333333333333333333333"
            + "44444444444444444444444444444444",
        "000102030405060708090a0b0c0d0e0f",
        "4f802da62a384555a19bc2b382eb25af",
        "",
        "e9b0bb8857818ce3201c3690d21daa7f264fb8ee93cc7a4674ea2fc32bf182fb"
            + "2a7e8ad51507ad4f31cefc2356fe7936a7f6e19f95e88fdbf17620916d3a6f3d"
            + "01fc17d358672f777fd4099246e436e167910be744b8315ae0eb6124590c5d8b"),
    // 192-bit keys
    new EaxTestVector(
        "",
        "03dd258601c1d4872a52b27892db0356911b2df1436dc7f4",
        "723cb2022102113018dcd2d204022114",
        "",
        "c472b1c6c22b4f2b7e02409499aa2ade"),
    new EaxTestVector(
        "",
        "d33dda72649575e42d6eb1f3255e686084b8a9cf4480803c",
        "ad2a1d2ef236dfaeb109ab29b1084d63",
        "fb9c0938a5d317fad5f43edc",
        "6edc358f22358e1d328c4c1cd98184c6"),
    new EaxTestVector(
        "4e43dbebe316b7d684b56236fdd928dd",
        "a36eed1cb54130f547664c184c249e777a3d8ba2e2251b58",
        "e9587847b1e81511e0643f7dda5b725c",
        "80c7cb954463b6067b081ff66b1d40cc",
        "e2645cd32a6e8c1e7cd1991d879b335756f848aba8e51f0b56712bb2889c4783"),
    // 256-bit keys
    new EaxTestVector(
        "13d106d7be0890093f44a457d4cc5309",
        "db50934278a8d8101d1c538acfbfaa13aba9fe53408b6205a0c996d53cf04e8d",
        "eaef04607a36b2e1b1c539bc335aee9a",
        "d50e7dbdcc7cf92822dd9dd762a0fc12",
        "2202165697a2d21316c5f65d2aedb3c52b5567b3f8a25e247cfda1f02bc6cf6f"),
    new EaxTestVector(
        "17672288fff3e93a45b3b951bbcfa8a4cb",
        "1cd28aca6542a4df7316b2c6e9232a4e2cc88cf7aaece33eec7da32ab514051f",
        "d219298abb115ccbb473cf8e2da9671a",
        "9c504ab2e5ce0f46844833aba6a11c9186e500239460bb26",
        "aa518b62c5422e56ce393951aa0441e99df8cafb1555d5a30c90391bb9272c32b9"),
  };

  @Test
  public void testEncryptDecrypt() throws Exception {
    byte[] aad = new byte[] {1, 2, 3};
    byte[] key = Random.randBytes(KEY_SIZE);
    AesEaxJce eax = new AesEaxJce(key, IV_SIZE);
    for (int messageSize = 0; messageSize < 75; messageSize++) {
      byte[] message = Random.randBytes(messageSize);
      byte[] ciphertext = eax.encrypt(message, aad);
      byte[] decrypted = eax.decrypt(ciphertext, aad);
      assertArrayEquals(message, decrypted);
    }
  }

  @Test
  public void testRegression() throws Exception {
    for (EaxTestVector t : EAX_TEST_VECTOR) {
      // TODO(bleichen): Skipping test with key sizes larger than 128 bits because of
      //   https://buganizer.corp.google.com/issues/35928521
      if (t.key.length > 16) {
        continue;
      }
      AesEaxJce eax = new AesEaxJce(t.key, t.ivSizeInBytes);
      // For this regression test we can only decrypt, since the AEAD interface
      // does not allow the caller to select the nonces. (Of course, that is on purpose).
      byte[] plaintext = eax.decrypt(t.ct, t.aad);
      assertArrayEquals(t.pt, plaintext);
    }
  }

  @Test
  public void testModifyCiphertext() throws Exception {
    testModifyCiphertext(16, 16);
    testModifyCiphertext(16, 12);
    // TODO(bleichen): Skipping test with key sizes larger than 128 bits because of
    //   https://buganizer.corp.google.com/issues/35928521
    // testModifyCiphertext(24, 16);
    // testModifyCiphertext(32, 16);
  }

  public void testModifyCiphertext(int keySizeInBytes, int ivSizeInBytes) throws Exception {
    byte[] aad = new byte[] {1, 2, 3};
    byte[] key = Random.randBytes(KEY_SIZE);
    byte[] message = Random.randBytes(32);
    AesEaxJce eax = new AesEaxJce(key, ivSizeInBytes);
    byte[] ciphertext = eax.encrypt(message, aad);

    // Flipping bits
    for (int b = 0; b < ciphertext.length; b++) {
      for (int bit = 0; bit < 8; bit++) {
        byte[] modified = Arrays.copyOf(ciphertext, ciphertext.length);
        modified[b] ^= (byte) (1 << bit);
        try {
          byte[] unused = eax.decrypt(modified, aad);
          fail("Decrypting modified ciphertext should fail");
        } catch (AEADBadTagException ex) {
          // This is expected.
        }
      }
    }

    // Truncate the message.
    for (int length = 0; length < ciphertext.length; length++) {
      byte[] modified = Arrays.copyOf(ciphertext, length);
      try {
        byte[] unused = eax.decrypt(modified, aad);
        fail("Decrypting modified ciphertext should fail");
      } catch (GeneralSecurityException ex) {
        // This is expected.
        // This could be a AeadBadTagException when the tag verification
        // fails or some not yet specified Exception when the ciphertext is too short.
        // In all cases a GeneralSecurityException or a subclass of it must be thrown.
      }
    }

    // Modify AAD
    for (int b = 0; b < aad.length; b++) {
      for (int bit = 0; bit < 8; bit++) {
        byte[] modified = Arrays.copyOf(aad, aad.length);
        modified[b] ^= (byte) (1 << bit);
        try {
          byte[] unused = eax.decrypt(ciphertext, modified);
          fail("Decrypting with modified aad should fail");
        } catch (AEADBadTagException ex) {
          // This is expected.
        }
      }
    }
  }

  @Test
  /**
   * A very basic test for asynchronous encryption.
   */
  public void testAsync() throws Exception {
    byte[] aad = new byte[] {1, 2, 3};
    byte[] key = Random.randBytes(KEY_SIZE);
    AesEaxJce eax = new AesEaxJce(key, IV_SIZE);
    byte[] plaintext = Random.randBytes(20);

    byte[] ciphertext = eax.asyncEncrypt(plaintext, aad).get();
    byte[] decrypted = eax.asyncDecrypt(ciphertext, aad).get();
    assertArrayEquals(plaintext, decrypted);
    for (int length = 0; length < ciphertext.length; length++) {
      byte[] truncated = Arrays.copyOf(ciphertext, length);
      try {
        byte[] unused = eax.asyncDecrypt(truncated, aad).get();
        fail("Decrypting a truncated ciphertext should fail");
      } catch (ExecutionException ex) {
        // The decryption should fail because the ciphertext has been truncated.
        assertTrue(ex.getCause() instanceof GeneralSecurityException);
      }
    }
  }
}
