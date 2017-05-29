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
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import com.google.crypto.tink.TestUtil;
import java.security.GeneralSecurityException;
import java.security.SignatureException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Unit tests for Ed25519.
 */
@RunWith(JUnit4.class)
public class Ed25519Test {

  @Test
  public void testSignVerifyRandomKeys() throws GeneralSecurityException {
    for (int i = 0; i < 1000; i++) {
      byte[] rand = Random.randBytes(new java.util.Random().nextInt(300));
      Ed25519Sign.KeyPair keyPair = Ed25519Sign.KeyPair.newKeyPair();
      Ed25519Sign signer = new Ed25519Sign(keyPair.getPrivateKey());
      Ed25519Verify verifier = new Ed25519Verify(keyPair.getPublicKey());
      byte[] s = signer.sign(rand);
      try {
        verifier.verify(s, rand);
      } catch (SignatureException e) {
        fail(String.format(
            "\n\nMessage: %s\nSignature: %s\nPrivateKey: %s\nPublicKey: %s\n",
            TestUtil.hexEncode(rand), TestUtil.hexEncode(s),
            TestUtil.hexEncode(keyPair.getPrivateKey()),
            TestUtil.hexEncode(keyPair.getPublicKey())));
      }
    }
  }

  private static class TestVectors {

    private String hexPublicKey = "";
    private String hexPrivateKey = "";
    private String hexMessage = "";
    private String hexSignature = "";

    TestVectors appendPublicKey(String publicKeyPart) {
      hexPublicKey += publicKeyPart;
      return this;
    }

    TestVectors appendPrivateKey(String privateKeyPart) {
      hexPrivateKey += privateKeyPart;
      return this;
    }

    TestVectors appendMessage(String messagePart) {
      hexMessage += messagePart;
      return this;
    }

    TestVectors appendSignature(String signaturePart) {
      hexSignature += signaturePart;
      return this;
    }

    void test() throws GeneralSecurityException {
      byte[] publicKey = TestUtil.hexDecode(hexPublicKey);
      byte[] privateKey = TestUtil.hexDecode(hexPrivateKey);
      byte[] message = TestUtil.hexDecode(hexMessage);
      Ed25519Sign signer = new Ed25519Sign(privateKey);
      Ed25519Verify verifier = new Ed25519Verify(publicKey);
      byte[] sig = signer.sign(message);
      assertEquals(hexSignature, TestUtil.hexEncode(sig));
      verifier.verify(sig, message);
    }

    void testSignForIllegalArgExp(String errorMsg) throws GeneralSecurityException  {
      try {
        Ed25519Sign signer = new Ed25519Sign(TestUtil.hexDecode(hexPrivateKey));
        signer.sign(TestUtil.hexDecode(hexMessage));
        fail("Expected IllegalArgumentException");
      } catch (IllegalArgumentException expected) {
        assertThat(expected).hasMessageThat().containsMatch(errorMsg);
      }
    }

    void testVerifyForIllegalArgExp(String errorMsg) throws GeneralSecurityException  {
      try {
        Ed25519Verify verifier = new Ed25519Verify(TestUtil.hexDecode(hexPublicKey));
        verifier.verify(TestUtil.hexDecode(hexSignature), TestUtil.hexDecode(hexMessage));
        fail("Expected IllegalArgumentException");
      } catch (IllegalArgumentException expected) {
        assertThat(expected).hasMessageThat().containsMatch(errorMsg);
      }
    }
  }

  @Test
  public void testSignThrowsIllegalArgExpWhenPrivateKeyLengthIsLessThan32()
      throws GeneralSecurityException {
    new TestVectors()
        .appendPublicKey("d75a980182b10ab7d54bfed3c964073a")
        .appendPublicKey("0ee172f3daa62325af021a68f707511a")
        .appendPrivateKey("9d61b19deffd5a60ba844af492ec")
        .testSignForIllegalArgExp("Given private key's length is not 32");
  }

  @Test
  public void testSignThrowsIllegalArgExpWhenPrivateKeyLengthIsGreaterThan32()
      throws GeneralSecurityException {
    new TestVectors()
        .appendPublicKey("d75a980182b10ab7d54bfed3c964073a")
        .appendPublicKey("0ee172f3daa62325af021a68f707511a")
        .appendPrivateKey("9d61b19deffd5a60ba844af492ec2cc4")
        .appendPrivateKey("4449c5697b326919703bac031cae7f0000")
        .testSignForIllegalArgExp("Given private key's length is not 32");
  }

  @Test
  public void testVerifyThrowsIllegalArgExpWhenSignatureLengthIsLessThan64()
      throws GeneralSecurityException {
    new TestVectors()
        .appendPublicKey("d75a980182b10ab7d54bfed3c964073a")
        .appendPublicKey("0ee172f3daa62325af021a68f707511a")
        .appendSignature("e5564300c360ac729086e2cc806e828a")
        .appendSignature("84877f1eb8e5d974d873e06522490155")
        .appendSignature("5fb8821590a33bacc61e39701cf9b46b")
        .appendSignature("d25bf5f0595bbe24655141438e7a10")
        .testVerifyForIllegalArgExp("The length of the signature is not 64");
  }

  @Test
  public void testVerifyThrowsIllegalArgExpWhenSignatureIsMalformed()
      throws GeneralSecurityException {
    new TestVectors()
        .appendPublicKey("d75a980182b10ab7d54bfed3c964073a")
        .appendPublicKey("0ee172f3daa62325af021a68f707511a")
        .appendSignature("e5564300c360ac729086e2cc806e828a")
        .appendSignature("84877f1eb8e5d974d873e06522490155")
        .appendSignature("5fb8821590a33bacc61e39701cf9b46b")
        .appendSignature("d25bf5f0595bbe24655141438e7a1021")
        .testVerifyForIllegalArgExp("Given signature's 3 most significant bits must be 0.");
  }

  @Test
  public void testVerifyThrowsIllegalArgExpWhenPublicKeyLengthIsLessThan32()
      throws GeneralSecurityException {
    new TestVectors()
        .appendPublicKey("d75a980182b10ab7d54bfed3c964073a")
        .appendPublicKey("0ee172f3daa62325af021a68f70751")
        .appendSignature("e5564300c360ac729086e2cc806e828a")
        .appendSignature("84877f1eb8e5d974d873e06522490155")
        .appendSignature("5fb8821590a33bacc61e39701cf9b46b")
        .appendSignature("d25bf5f0595bbe24655141438e7a1011")
        .testVerifyForIllegalArgExp("Given public key's length is not 32.");
  }

  @Test
  public void testVerifyThrowsIllegalArgExpWhenPublicKeyLengthIsGreaterThan32()
      throws GeneralSecurityException {
    new TestVectors()
        .appendPublicKey("d75a980182b10ab7d54bfed3c964073a")
        .appendPublicKey("0ee172f3daa62325af021a68f707511aaa")
        .appendSignature("e5564300c360ac729086e2cc806e828a")
        .appendSignature("84877f1eb8e5d974d873e06522490155")
        .appendSignature("5fb8821590a33bacc61e39701cf9b46b")
        .appendSignature("d25bf5f0595bbe24655141438e7a1011")
        .testVerifyForIllegalArgExp("Given public key's length is not 32.");
  }

  // Test vectors from https://tools.ietf.org/html/rfc8032#section-7.1
  @Test
  public void testVector1() throws GeneralSecurityException {
    new TestVectors()
        .appendPublicKey("d75a980182b10ab7d54bfed3c964073a")
        .appendPublicKey("0ee172f3daa62325af021a68f707511a")
        .appendPrivateKey("9d61b19deffd5a60ba844af492ec2cc4")
        .appendPrivateKey("4449c5697b326919703bac031cae7f60")
        .appendMessage("")
        .appendSignature("e5564300c360ac729086e2cc806e828a")
        .appendSignature("84877f1eb8e5d974d873e06522490155")
        .appendSignature("5fb8821590a33bacc61e39701cf9b46b")
        .appendSignature("d25bf5f0595bbe24655141438e7a100b")
        .test();
  }

  @Test
  public void testVector2() throws GeneralSecurityException {
    new TestVectors()
        .appendPublicKey("3d4017c3e843895a92b70aa74d1b7ebc")
        .appendPublicKey("9c982ccf2ec4968cc0cd55f12af4660c")
        .appendPrivateKey("4ccd089b28ff96da9db6c346ec114e0f")
        .appendPrivateKey("5b8a319f35aba624da8cf6ed4fb8a6fb")
        .appendMessage("72")
        .appendSignature("92a009a9f0d4cab8720e820b5f642540")
        .appendSignature("a2b27b5416503f8fb3762223ebdb69da")
        .appendSignature("085ac1e43e15996e458f3613d0f11d8c")
        .appendSignature("387b2eaeb4302aeeb00d291612bb0c00")
        .test();
  }

  @Test
  public void testVector3() throws GeneralSecurityException {
    new TestVectors()
        .appendPublicKey("fc51cd8e6218a1a38da47ed00230f058")
        .appendPublicKey("0816ed13ba3303ac5deb911548908025")
        .appendPrivateKey("c5aa8df43f9f837bedb7442f31dcb7b1")
        .appendPrivateKey("66d38535076f094b85ce3a2e0b4458f7")
        .appendMessage("af82")
        .appendSignature("6291d657deec24024827e69c3abe01a3")
        .appendSignature("0ce548a284743a445e3680d7db5ac3ac")
        .appendSignature("18ff9b538d16f290ae67f760984dc659")
        .appendSignature("4a7c15e9716ed28dc027beceea1ec40a")
        .test();
  }

  @Test
  public void testVector1024() throws GeneralSecurityException {
    new TestVectors()
        .appendPublicKey("278117fc144c72340f67d0f2316e8386")
        .appendPublicKey("ceffbf2b2428c9c51fef7c597f1d426e")
        .appendPrivateKey("f5e5767cf153319517630f226876b86c")
        .appendPrivateKey("8160cc583bc013744c6bf255f5cc0ee5")
        .appendMessage("08b8b2b733424243760fe426a4b54908")
        .appendMessage("632110a66c2f6591eabd3345e3e4eb98")
        .appendMessage("fa6e264bf09efe12ee50f8f54e9f77b1")
        .appendMessage("e355f6c50544e23fb1433ddf73be84d8")
        .appendMessage("79de7c0046dc4996d9e773f4bc9efe57")
        .appendMessage("38829adb26c81b37c93a1b270b20329d")
        .appendMessage("658675fc6ea534e0810a4432826bf58c")
        .appendMessage("941efb65d57a338bbd2e26640f89ffbc")
        .appendMessage("1a858efcb8550ee3a5e1998bd177e93a")
        .appendMessage("7363c344fe6b199ee5d02e82d522c4fe")
        .appendMessage("ba15452f80288a821a579116ec6dad2b")
        .appendMessage("3b310da903401aa62100ab5d1a36553e")
        .appendMessage("06203b33890cc9b832f79ef80560ccb9")
        .appendMessage("a39ce767967ed628c6ad573cb116dbef")
        .appendMessage("efd75499da96bd68a8a97b928a8bbc10")
        .appendMessage("3b6621fcde2beca1231d206be6cd9ec7")
        .appendMessage("aff6f6c94fcd7204ed3455c68c83f4a4")
        .appendMessage("1da4af2b74ef5c53f1d8ac70bdcb7ed1")
        .appendMessage("85ce81bd84359d44254d95629e9855a9")
        .appendMessage("4a7c1958d1f8ada5d0532ed8a5aa3fb2")
        .appendMessage("d17ba70eb6248e594e1a2297acbbb39d")
        .appendMessage("502f1a8c6eb6f1ce22b3de1a1f40cc24")
        .appendMessage("554119a831a9aad6079cad88425de6bd")
        .appendMessage("e1a9187ebb6092cf67bf2b13fd65f270")
        .appendMessage("88d78b7e883c8759d2c4f5c65adb7553")
        .appendMessage("878ad575f9fad878e80a0c9ba63bcbcc")
        .appendMessage("2732e69485bbc9c90bfbd62481d9089b")
        .appendMessage("eccf80cfe2df16a2cf65bd92dd597b07")
        .appendMessage("07e0917af48bbb75fed413d238f5555a")
        .appendMessage("7a569d80c3414a8d0859dc65a46128ba")
        .appendMessage("b27af87a71314f318c782b23ebfe808b")
        .appendMessage("82b0ce26401d2e22f04d83d1255dc51a")
        .appendMessage("ddd3b75a2b1ae0784504df543af8969b")
        .appendMessage("e3ea7082ff7fc9888c144da2af58429e")
        .appendMessage("c96031dbcad3dad9af0dcbaaaf268cb8")
        .appendMessage("fcffead94f3c7ca495e056a9b47acdb7")
        .appendMessage("51fb73e666c6c655ade8297297d07ad1")
        .appendMessage("ba5e43f1bca32301651339e22904cc8c")
        .appendMessage("42f58c30c04aafdb038dda0847dd988d")
        .appendMessage("cda6f3bfd15c4b4c4525004aa06eeff8")
        .appendMessage("ca61783aacec57fb3d1f92b0fe2fd1a8")
        .appendMessage("5f6724517b65e614ad6808d6f6ee34df")
        .appendMessage("f7310fdc82aebfd904b01e1dc54b2927")
        .appendMessage("094b2db68d6f903b68401adebf5a7e08")
        .appendMessage("d78ff4ef5d63653a65040cf9bfd4aca7")
        .appendMessage("984a74d37145986780fc0b16ac451649")
        .appendMessage("de6188a7dbdf191f64b5fc5e2ab47b57")
        .appendMessage("f7f7276cd419c17a3ca8e1b939ae49e4")
        .appendMessage("88acba6b965610b5480109c8b17b80e1")
        .appendMessage("b7b750dfc7598d5d5011fd2dcc5600a3")
        .appendMessage("2ef5b52a1ecc820e308aa342721aac09")
        .appendMessage("43bf6686b64b2579376504ccc493d97e")
        .appendMessage("6aed3fb0f9cd71a43dd497f01f17c0e2")
        .appendMessage("cb3797aa2a2f256656168e6c496afc5f")
        .appendMessage("b93246f6b1116398a346f1a641f3b041")
        .appendMessage("e989f7914f90cc2c7fff357876e506b5")
        .appendMessage("0d334ba77c225bc307ba537152f3f161")
        .appendMessage("0e4eafe595f6d9d90d11faa933a15ef1")
        .appendMessage("369546868a7f3a45a96768d40fd9d034")
        .appendMessage("12c091c6315cf4fde7cb68606937380d")
        .appendMessage("b2eaaa707b4c4185c32eddcdd306705e")
        .appendMessage("4dc1ffc872eeee475a64dfac86aba41c")
        .appendMessage("0618983f8741c5ef68d3a101e8a3b8ca")
        .appendMessage("c60c905c15fc910840b94c00a0b9d0")
        .appendSignature("0aab4c900501b3e24d7cdf4663326a3a")
        .appendSignature("87df5e4843b2cbdb67cbf6e460fec350")
        .appendSignature("aa5371b1508f9f4528ecea23c436d94b")
        .appendSignature("5e8fcd4f681e30a6ac00a9704a188a03")
        .test();
  }

  @Test
  public void testVectorSHAabc() throws GeneralSecurityException {
    new TestVectors()
        .appendPublicKey("ec172b93ad5e563bf4932c70e1245034")
        .appendPublicKey("c35467ef2efd4d64ebf819683467e2bf")
        .appendPrivateKey("833fe62409237b9d62ec77587520911e")
        .appendPrivateKey("9a759cec1d19755b7da901b96dca3d42")
        .appendMessage("ddaf35a193617abacc417349ae204131")
        .appendMessage("12e6fa4e89a97ea20a9eeee64b55d39a")
        .appendMessage("2192992a274fc1a836ba3c23a3feebbd")
        .appendMessage("454d4423643ce80e2a9ac94fa54ca49f")
        .appendSignature("dc2a4459e7369633a52b1bf277839a00")
        .appendSignature("201009a3efbf3ecb69bea2186c26b589")
        .appendSignature("09351fc9ac90b3ecfdfbc7c66431e030")
        .appendSignature("3dca179c138ac17ad9bef1177331a704")
        .test();
  }
}
