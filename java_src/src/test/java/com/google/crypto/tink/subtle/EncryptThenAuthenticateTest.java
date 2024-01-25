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

package com.google.crypto.tink.subtle;

import static com.google.common.truth.Truth.assertThat;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.fail;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.CryptoFormat;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.aead.AesCtrHmacAeadKey;
import com.google.crypto.tink.aead.AesCtrHmacAeadParameters;
import com.google.crypto.tink.aead.AesCtrHmacAeadParameters.HashType;
import com.google.crypto.tink.aead.AesCtrHmacAeadParameters.Variant;
import com.google.crypto.tink.util.SecretBytes;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.util.Arrays;
import org.junit.Test;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

/** Unit tests for {@link EncryptThenAuthenticate}. */
@RunWith(Theories.class)
public class EncryptThenAuthenticateTest {
  private static class RFCTestVector {
    public byte[] encKey;
    public byte[] macKey;
    public byte[] ciphertext;
    public byte[] aad;
    public String macAlg;
    public int ivSize;
    public int tagLength;

    public RFCTestVector(
        String macKey,
        String encKey,
        String ciphertext,
        String aad,
        String macAlg,
        int ivSize,
        int tagLength) {
      try {
        this.encKey = Hex.decode(encKey);
        this.macKey = Hex.decode(macKey);
        this.ciphertext = Hex.decode(ciphertext);
        this.aad = Hex.decode(aad);
        this.macAlg = macAlg;
        this.ivSize = ivSize;
        this.tagLength = tagLength;
      } catch (Exception ignored) {
        // Ignored
      }
    }
  }

  // Test data from https://tools.ietf.org/html/draft-mcgrew-aead-aes-cbc-hmac-sha2-05. As we use
  // CTR while the RFC uses CBC mode, it's not possible to compare plaintexts. However, the test is
  // still valuable to make sure that we correctly compute HMAC over ciphertext and aad.
  @DataPoints("rfcTestVectors")
  public static final RFCTestVector[] RFC_TEST_VECTORS = {
    new RFCTestVector(
        "000102030405060708090a0b0c0d0e0f",
        "101112131415161718191a1b1c1d1e1f",
        "1af38c2dc2b96ffdd86694092341bc04"
            + "c80edfa32ddf39d5ef00c0b468834279"
            + "a2e46a1b8049f792f76bfe54b903a9c9"
            + "a94ac9b47ad2655c5f10f9aef71427e2"
            + "fc6f9b3f399a221489f16362c7032336"
            + "09d45ac69864e3321cf82935ac4096c8"
            + "6e133314c54019e8ca7980dfa4b9cf1b"
            + "384c486f3a54c51078158ee5d79de59f"
            + "bd34d848b3d69550a67646344427ade5"
            + "4b8851ffb598f7f80074b9473c82e2db"
            + "652c3fa36b0a7c5b3219fab3a30bc1c4",
        "546865207365636f6e64207072696e6369706c65206f662041756775737465204b6572636b686f666673",
        "HMACSHA256",
        16,
        16),
    new RFCTestVector(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
        "1af38c2dc2b96ffdd86694092341bc04"
            + "4affaaadb78c31c5da4b1b590d10ffbd"
            + "3dd8d5d302423526912da037ecbcc7bd"
            + "822c301dd67c373bccb584ad3e9279c2"
            + "e6d12a1374b77f077553df829410446b"
            + "36ebd97066296ae6427ea75c2e0846a1"
            + "1a09ccf5370dc80bfecbad28c73f09b3"
            + "a3b75e662a2594410ae496b2e2e6609e"
            + "31e6e02cc837f053d21f37ff4f51950b"
            + "be2638d09dd7a4930930806d0703b1f6"
            + "4dd3b4c088a7f45c216839645b2012bf"
            + "2e6269a8c56a816dbc1b267761955bc5",
        "546865207365636f6e64207072696e6369706c65206f662041756775737465204b6572636b686f666673",
        "HMACSHA512",
        16,
        32)
  };

  @Test
  public void testRFCVectors() throws Exception {
    for (int i = 0; i < RFC_TEST_VECTORS.length; i++) {
      RFCTestVector t = RFC_TEST_VECTORS[i];
      Aead aead = getAead(t.macKey, t.encKey, t.ivSize, t.tagLength, t.macAlg);
      Object unused = aead.decrypt(t.ciphertext, t.aad);
    }
  }

  @Test
  public void testBitFlipCiphertext() throws Exception {
    Aead aead = getAead(Random.randBytes(16), Random.randBytes(16), 16, 16, "HMACSHA256");
    byte[] plaintext = Random.randBytes(1001);
    byte[] aad = Random.randBytes(13);
    byte[] ciphertext = aead.encrypt(plaintext, aad);
    for (int i = 0; i < ciphertext.length; i++) {
      for (int j = 0; j < 8; j++) {
        byte[] c1 = Arrays.copyOf(ciphertext, ciphertext.length);
        c1[i] = (byte) (c1[i] ^ (1 << j));
        assertThrows(GeneralSecurityException.class, () -> aead.decrypt(c1, aad));
      }
    }
  }

  @Test
  public void testBitFlipAad() throws Exception {
    Aead aead = getAead(Random.randBytes(16), Random.randBytes(16), 16, 16, "HMACSHA256");
    byte[] plaintext = Random.randBytes(1001);
    byte[] aad = Random.randBytes(13);
    byte[] ciphertext = aead.encrypt(plaintext, aad);
    for (int i = 0; i < aad.length; i++) {
      for (int j = 0; j < 8; j++) {
        byte[] aad1 = Arrays.copyOf(aad, aad.length);
        aad1[i] = (byte) (aad1[i] ^ (1 << j));
        assertThrows(GeneralSecurityException.class, () -> aead.decrypt(ciphertext, aad1));
      }
    }
  }

  @Test
  public void testEncryptDecrypt() throws Exception {
    Aead aead = getAead(Random.randBytes(16), Random.randBytes(16), 16, 16, "HMACSHA256");
    byte[] plaintext = Random.randBytes(1001);
    byte[] aad = Random.randBytes(13);
    byte[] ciphertext = aead.encrypt(plaintext, aad);
    try {
      byte[] plaintext1 = aead.decrypt(ciphertext, aad);
      assertArrayEquals(plaintext, plaintext1);
    } catch (GeneralSecurityException e) {
      fail("Valid ciphertext and aad, should have passed: " + e);
    }
  }

  @Test
  public void testNullPlaintextOrCiphertext() throws Exception {
    Aead aead = getAead(Random.randBytes(16), Random.randBytes(16), 16, 16, "HMACSHA256");
    byte[] aad = new byte[] {1, 2, 3};
    assertThrows(
        NullPointerException.class,
        () -> {
          byte[] unused = aead.encrypt(null, aad);
        });
    assertThrows(
        NullPointerException.class,
        () -> {
          byte[] unused = aead.encrypt(null, null);
        });
    assertThrows(
        NullPointerException.class,
        () -> {
          byte[] unused = aead.decrypt(null, aad);
        });
    assertThrows(
        NullPointerException.class,
        () -> {
          byte[] unused = aead.decrypt(null, null);
        });
  }

  @Test
  public void testEmptyAssociatedData() throws Exception {
    Aead aead = getAead(Random.randBytes(16), Random.randBytes(16), 16, 16, "HMACSHA256");
    byte[] aad = new byte[0];
    byte[] plaintext = Random.randBytes(1001);
    {  // encrypting with aad as a 0-length array
      byte[] ciphertext = aead.encrypt(plaintext, aad);
      byte[] decrypted = aead.decrypt(ciphertext, aad);
      assertArrayEquals(plaintext, decrypted);
      byte[] decrypted2 = aead.decrypt(ciphertext, null);
      assertArrayEquals(plaintext, decrypted2);
      byte[] badAad = new byte[] {1, 2, 3};
      assertThrows(
          GeneralSecurityException.class,
          () -> {
            byte[] unused = aead.decrypt(ciphertext, badAad);
          });
    }
    {  // encrypting with aad equal to null
      byte[] ciphertext = aead.encrypt(plaintext, null);
      byte[] decrypted = aead.decrypt(ciphertext, aad);
      assertArrayEquals(plaintext, decrypted);
      byte[] decrypted2 = aead.decrypt(ciphertext, null);
      assertArrayEquals(plaintext, decrypted2);
      byte[] badAad = new byte[] {1, 2, 3};
      assertThrows(
          GeneralSecurityException.class,
          () -> {
            byte[] unused = aead.decrypt(ciphertext, badAad);
          });
    }
  }

  @Test
  public void testTruncation() throws Exception {
    Aead aead = getAead(Random.randBytes(16), Random.randBytes(16), 16, 16, "HMACSHA256");
    byte[] plaintext = Random.randBytes(1001);
    byte[] aad = Random.randBytes(13);
    byte[] ciphertext = aead.encrypt(plaintext, aad);
    for (int i = 1; i < ciphertext.length; i++) {
      byte[] c1 = Arrays.copyOf(ciphertext, ciphertext.length - i);
      assertThrows(GeneralSecurityException.class, () -> aead.decrypt(c1, aad));
    }
  }

  @Theory
  public void create_RFCVectors_works(@FromDataPoints("rfcTestVectors") RFCTestVector t)
      throws Exception {
    AesCtrHmacAeadParameters.HashType hashType;
    switch (t.macAlg) {
      case "HMACSHA256":
        hashType = HashType.SHA256;
        break;
      case "HMACSHA512":
        hashType = HashType.SHA512;
        break;
      default:
        throw new InvalidAlgorithmParameterException("unexpected hash type in RFC test vector");
    }
    AesCtrHmacAeadParameters parameters =
        AesCtrHmacAeadParameters.builder()
            .setAesKeySizeBytes(t.encKey.length)
            .setHmacKeySizeBytes(t.macKey.length)
            .setHashType(hashType)
            .setTagSizeBytes(t.tagLength)
            .setIvSizeBytes(t.ivSize)
            .setVariant(Variant.NO_PREFIX)
            .build();
    AesCtrHmacAeadKey key =
        AesCtrHmacAeadKey.builder()
            .setAesKeyBytes(SecretBytes.copyFrom(t.encKey, InsecureSecretKeyAccess.get()))
            .setHmacKeyBytes(SecretBytes.copyFrom(t.macKey, InsecureSecretKeyAccess.get()))
            .setParameters(parameters)
            .build();

    Aead aead = EncryptThenAuthenticate.create(key);

    Object unused = aead.decrypt(t.ciphertext, t.aad);
  }

  @Test
  public void create_encryptDecryptRaw_works() throws Exception {
    AesCtrHmacAeadParameters parameters =
        AesCtrHmacAeadParameters.builder()
            .setAesKeySizeBytes(32)
            .setHmacKeySizeBytes(16)
            .setTagSizeBytes(17)
            .setHashType(HashType.SHA512)
            .setIvSizeBytes(16)
            .setVariant(Variant.NO_PREFIX)
            .build();
    AesCtrHmacAeadKey key =
        AesCtrHmacAeadKey.builder()
            .setAesKeyBytes(SecretBytes.randomBytes(32))
            .setHmacKeyBytes(SecretBytes.randomBytes(16))
            .setParameters(parameters)
            .build();
    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] aad = "aad".getBytes(UTF_8);

    Aead aead = EncryptThenAuthenticate.create(key);

    assertThat(aead.decrypt(aead.encrypt(plaintext, aad), aad)).isEqualTo(plaintext);
  }

  @Test
  public void create_encryptTink_hasPrefix() throws Exception {
    AesCtrHmacAeadParameters parameters =
        AesCtrHmacAeadParameters.builder()
            .setAesKeySizeBytes(32)
            .setHmacKeySizeBytes(32)
            .setHashType(HashType.SHA512)
            .setTagSizeBytes(17)
            .setIvSizeBytes(15)
            .setVariant(Variant.TINK)
            .build();
    AesCtrHmacAeadKey key =
        AesCtrHmacAeadKey.builder()
            .setAesKeyBytes(SecretBytes.randomBytes(32))
            .setHmacKeyBytes(SecretBytes.randomBytes(32))
            .setParameters(parameters)
            .setIdRequirement(42)
            .build();
    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] aad = "aad".getBytes(UTF_8);

    Aead aead = EncryptThenAuthenticate.create(key);
    byte[] ciphertext = aead.encrypt(plaintext, aad);

    assertThat(Arrays.copyOf(ciphertext, CryptoFormat.NON_RAW_PREFIX_SIZE))
        .isEqualTo(key.getOutputPrefix().toByteArray());
  }

  @Test
  public void create_encryptDecryptTink_works() throws Exception {
    AesCtrHmacAeadParameters parameters =
        AesCtrHmacAeadParameters.builder()
            .setAesKeySizeBytes(32)
            .setHmacKeySizeBytes(32)
            .setHashType(HashType.SHA256)
            .setTagSizeBytes(17)
            .setIvSizeBytes(14)
            .setVariant(Variant.TINK)
            .build();
    AesCtrHmacAeadKey key =
        AesCtrHmacAeadKey.builder()
            .setAesKeyBytes(SecretBytes.randomBytes(32))
            .setHmacKeyBytes(SecretBytes.randomBytes(32))
            .setParameters(parameters)
            .setIdRequirement(42)
            .build();
    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] aad = "aad".getBytes(UTF_8);

    Aead aead = EncryptThenAuthenticate.create(key);

    assertThat(aead.decrypt(aead.encrypt(plaintext, aad), aad)).isEqualTo(plaintext);
  }

  @Test
  public void create_encryptCrunchy_hasPrefix() throws Exception {
    AesCtrHmacAeadParameters parameters =
        AesCtrHmacAeadParameters.builder()
            .setAesKeySizeBytes(16)
            .setHmacKeySizeBytes(32)
            .setHashType(HashType.SHA256)
            .setTagSizeBytes(18)
            .setIvSizeBytes(13)
            .setVariant(Variant.CRUNCHY)
            .build();
    AesCtrHmacAeadKey key =
        AesCtrHmacAeadKey.builder()
            .setAesKeyBytes(SecretBytes.randomBytes(16))
            .setHmacKeyBytes(SecretBytes.randomBytes(32))
            .setParameters(parameters)
            .setIdRequirement(42)
            .build();
    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] aad = "aad".getBytes(UTF_8);

    Aead aead = EncryptThenAuthenticate.create(key);
    byte[] ciphertext = aead.encrypt(plaintext, aad);

    assertThat(Arrays.copyOf(ciphertext, CryptoFormat.NON_RAW_PREFIX_SIZE))
        .isEqualTo(key.getOutputPrefix().toByteArray());
  }

  @Test
  public void create_encryptDecryptCrunchy_works() throws Exception {
    AesCtrHmacAeadParameters parameters =
        AesCtrHmacAeadParameters.builder()
            .setAesKeySizeBytes(32)
            .setHmacKeySizeBytes(16)
            .setHashType(HashType.SHA512)
            .setTagSizeBytes(16)
            .setIvSizeBytes(12)
            .setVariant(Variant.CRUNCHY)
            .build();
    AesCtrHmacAeadKey key =
        AesCtrHmacAeadKey.builder()
            .setAesKeyBytes(SecretBytes.randomBytes(32))
            .setHmacKeyBytes(SecretBytes.randomBytes(16))
            .setParameters(parameters)
            .setIdRequirement(42)
            .build();
    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] aad = "aad".getBytes(UTF_8);

    Aead aead = EncryptThenAuthenticate.create(key);

    assertThat(aead.decrypt(aead.encrypt(plaintext, aad), aad)).isEqualTo(plaintext);
  }

  @Test
  public void create_bitFlipCiphertext_throws() throws Exception {
    AesCtrHmacAeadParameters parameters =
        AesCtrHmacAeadParameters.builder()
            .setAesKeySizeBytes(32)
            .setHmacKeySizeBytes(16)
            .setHashType(HashType.SHA512)
            .setTagSizeBytes(16)
            .setIvSizeBytes(12)
            .setVariant(Variant.CRUNCHY)
            .build();
    AesCtrHmacAeadKey key =
        AesCtrHmacAeadKey.builder()
            .setAesKeyBytes(SecretBytes.randomBytes(32))
            .setHmacKeyBytes(SecretBytes.randomBytes(16))
            .setParameters(parameters)
            .setIdRequirement(42)
            .build();
    byte[] plaintext = Random.randBytes(1001);
    byte[] aad = Random.randBytes(13);

    Aead aead = EncryptThenAuthenticate.create(key);
    byte[] ciphertext = aead.encrypt(plaintext, aad);

    for (int i = 0; i < ciphertext.length; i++) {
      for (int j = 0; j < 8; j++) {
        byte[] c1 = Arrays.copyOf(ciphertext, ciphertext.length);
        c1[i] = (byte) (c1[i] ^ (1 << j));
        assertThrows(GeneralSecurityException.class, () -> aead.decrypt(c1, aad));
      }
    }
  }

  private Aead getAead(byte[] hmacKey, byte[] encKey, int ivSize, int tagLength, String macAlg)
      throws Exception {
    return EncryptThenAuthenticate.newAesCtrHmac(encKey, ivSize, macAlg, hmacKey, tagLength);
  }
}
