// Copyright 2018 Google Inc.
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
package com.google.crypto.tink.signature;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.fail;

import com.google.crypto.tink.PublicKeySign;
import com.google.crypto.tink.PublicKeyVerify;
import com.google.crypto.tink.internal.KeyTypeManager;
import com.google.crypto.tink.proto.HashType;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.proto.RsaSsaPssKeyFormat;
import com.google.crypto.tink.proto.RsaSsaPssParams;
import com.google.crypto.tink.proto.RsaSsaPssPrivateKey;
import com.google.crypto.tink.proto.RsaSsaPssPublicKey;
import com.google.crypto.tink.subtle.Random;
import com.google.crypto.tink.testing.TestUtil;
import com.google.protobuf.ByteString;
import java.security.GeneralSecurityException;
import java.security.spec.RSAKeyGenParameterSpec;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for RsaSsaPssVerifyKeyManager. */
@RunWith(JUnit4.class)
public class RsaSsaPssVerifyKeyManagerTest {
  private final RsaSsaPssSignKeyManager signManager = new RsaSsaPssSignKeyManager();
  private final KeyTypeManager.KeyFactory<RsaSsaPssKeyFormat, RsaSsaPssPrivateKey> factory =
      signManager.keyFactory();

  private final RsaSsaPssVerifyKeyManager verifyManager = new RsaSsaPssVerifyKeyManager();

  static class NistTestVector {
    byte[] msg;
    byte[] sig;
    RsaSsaPssPublicKey publicKeyProto;

    public NistTestVector(
        String modulus,
        String exponent,
        String msg,
        String sig,
        HashType sigHash,
        HashType mgf1Hash,
        int saltLength)
        throws Exception {
      this.msg = TestUtil.hexDecode(msg);
      this.sig = TestUtil.hexDecode(sig);
      this.publicKeyProto =
          TestUtil.createRsaSsaPssPubKey(
              TestUtil.hexDecode(modulus),
              TestUtil.hexDecode(exponent),
              sigHash,
              mgf1Hash,
              saltLength);
    }
  }

  // Test vector from
  // https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/Digital-Signatures
  static NistTestVector[] nistTestVectors;

  @BeforeClass
  public static void setUpNistTestVectors() throws Exception {
    nistTestVectors =
        new NistTestVector[] {
          new NistTestVector(
              "a47d04e7cacdba4ea26eca8a4c6e14563c2ce03b623b768c0d49868a57121301dbf783d82f4c055e73960e70550187d0af62ac3496f0a3d9103c2eb7919a72752fa7ce8c688d81e3aee99468887a15288afbb7acb845b7c522b5c64e678fcd3d22feb84b44272700be527d2b2025a3f83c2383bf6a39cf5b4e48b3cf2f56eef0dfff18555e31037b915248694876f3047814415164f2c660881e694b58c28038a032ad25634aad7b39171dee368e3d59bfb7299e4601d4587e68caaf8db457b75af42fc0cf1ae7caced286d77fac6cedb03ad94f1433d2c94d08e60bc1fdef0543cd2951e765b38230fdd18de5d2ca627ddc032fe05bbd2ff21e2db1c2f94d8b",
              "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010e43f",
              "e002377affb04f0fe4598de9d92d31d6c786040d5776976556a2cfc55e54a1dcb3cb1b126bd6a4bed2a184990ccea773fcc79d246553e6c64f686d21ad4152673cafec22aeb40f6a084e8a5b4991f4c64cf8a927effd0fd775e71e8329e41fdd4457b3911173187b4f09a817d79ea2397fc12dfe3d9c9a0290c8ead31b6690a6",
              "4f9b425c2058460e4ab2f5c96384da2327fd29150f01955a76b4efe956af06dc08779a374ee4607eab61a93adc5608f4ec36e47f2a0f754e8ff839a8a19b1db1e884ea4cf348cd455069eb87afd53645b44e28a0a56808f5031da5ba9112768dfbfca44ebe63a0c0572b731d66122fb71609be1480faa4e4f75e43955159d70f081e2a32fbb19a48b9f162cf6b2fb445d2d6994bc58910a26b5943477803cdaaa1bd74b0da0a5d053d8b1dc593091db5388383c26079f344e2aea600d0e324164b450f7b9b465111b7265f3b1b063089ae7e2623fc0fda8052cf4bf3379102fbf71d7c98e8258664ceed637d20f95ff0111881e650ce61f251d9c3a629ef222d",
              HashType.SHA256,
              HashType.SHA256,
              32),
          new NistTestVector(
              "99a5c8d094a5f917034667a0408b7ecfcaacc3f9784444e21773c3461ec355f0d0f52a5db0568a71d388696788ef66ae7340c6b28dbf925fe83557986575f79cca69217221397ed5808a26f7e7e714c93235f914d45c4a9af4619b20f511ad644bd3412dfdf0ff717f7aac746f310bfa9a141ac3dbf01c1fc74febd197938419c262293505c35f402f9053ad13c51a5960ecde55ec829e953f941af733e58705913767e7a7200d1d09e7e7e2d269fa29a558bb16304b059f13f4ca560a8101fe3720b4a779ec126427326caa132a3d3611d7dbc50336fac789ec406b397e1e36d7daf9b624bf639c82b859288747690c730c980b2f5a239dd95ad5389a2ec90c5778604713710383ae55d4d28c06d4ac26f0d1231f1d6762c8e0d918118156bc637760daea184746b8dcf6f61db274a7ddceaa074937ababad4549b97ab992494a807208abd789823f5d75c4b994089c8072cfc254e0d8202fd896476e96ad9d309a0e8e7301282f07eb2ae8edefb7dbbe13b96e8b4024c6b84de0a05e150285",
              "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008a649",
              "cc21593a6a0f737e2970b7c07984b070d761726296a07e24e056e68ff846b29cc1548179843d74dcee86479858b2c16e4cb84f2544b4ecdcb4dd43a04bb7183a768ae44a2712bf9ad47883acc2812f958306890ebea408c92eb4f001ed7dbf55f3a9c8d6d9f61e5fe32eb3253e59c18e863169478cd69b9155c335db66016f96",
              "0aa572a6845b870b8909a683bb7e6e7616f77beff28746116d8bc4b7335546b51e8006ed0fc9a0d66f63ce0b9ebf792d7efd4305d7624d545400a5fd6a06b78f174b86803f7cd1cc93e3a97286f0ea590e40ff26195aa219fe1510a016785223606d9311a16c59a8fe4a6da6ecd0c1d7775039290c2aaa17ed1eb1b54374f7e572db13cca3a638575f8004aa54a2fa98422fc07e43ad3a20dd93001493442677d883914dc74ec1cbebbbd3d2b6bad4666d91457b69b46a1a61f21298f1a67942ec86c876322dd366ed167814e9c8fc9040c5b4b7a859bbd880cb6bc241b9e327ce779e0783b1cf445e0b2f5771b3f5822a1364391c154dc506fff1fb9d9a35f80199a6b30b4b92b92619a40e21aea19284015863c44866c61ed904a7ad19ee04d966c0aae390636243565581ff20bd6e3cfb6e31f5afba964b311dc2d023a21998c8dd50ca453699190bd467429e2f88ace29c4d1da4da61aac1eda2380230aa8dbb63c75a3c1ec04da3a1f880c9c747acdb74a8395af58f5f044015ccaf6e94",
              HashType.SHA512,
              HashType.SHA512,
              0),
        };
  }

  @Test
  public void basics() throws Exception {
    assertThat(verifyManager.getKeyType())
        .isEqualTo("type.googleapis.com/google.crypto.tink.RsaSsaPssPublicKey");
    assertThat(verifyManager.getVersion()).isEqualTo(0);
    assertThat(verifyManager.keyMaterialType()).isEqualTo(KeyMaterialType.ASYMMETRIC_PUBLIC);
  }

  @Test
  public void validateKey_empty_throws() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () -> verifyManager.validateKey(RsaSsaPssPublicKey.getDefaultInstance()));
  }

  @Test
  public void validateKey_generated() throws Exception {
    if (TestUtil.isTsan()) {
      // factory.createKey is too slow in Tsan.
      return;
    }

    RsaSsaPssKeyFormat keyFormat =
        RsaSsaPssKeyFormat.newBuilder()
            .setParams(
                RsaSsaPssParams.newBuilder()
                    .setSigHash(HashType.SHA256)
                    .setMgf1Hash(HashType.SHA256)
                    .setSaltLength(32))
            .setModulusSizeInBits(3072)
            .setPublicExponent(ByteString.copyFrom(RSAKeyGenParameterSpec.F4.toByteArray()))
            .build();
    RsaSsaPssPrivateKey privateKey = factory.createKey(keyFormat);
    RsaSsaPssPublicKey publicKey = signManager.getPublicKey(privateKey);
    verifyManager.validateKey(publicKey);
  }

  @Test
  public void validateKey_testVector() throws Exception {
    if (TestUtil.isTsan()) {
      // factory.createKey is too slow in Tsan.
      return;
    }
    
    RsaSsaPssPublicKey publicKey = nistTestVectors[0].publicKeyProto;
    verifyManager.validateKey(publicKey);
  }

  @Test
  public void validateKey_wrongVersion() throws Exception {
    RsaSsaPssPublicKey publicKey = nistTestVectors[0].publicKeyProto;

    RsaSsaPssPublicKey invalidKey = RsaSsaPssPublicKey.newBuilder(publicKey).setVersion(1).build();
    assertThrows(GeneralSecurityException.class, () -> verifyManager.validateKey(invalidKey));
  }

  @Test
  public void validateKey_smallModulus() throws Exception {
    RsaSsaPssPublicKey publicKey = nistTestVectors[0].publicKeyProto;

    RsaSsaPssPublicKey invalidKey =
        RsaSsaPssPublicKey.newBuilder(publicKey)
            .setN(ByteString.copyFrom(TestUtil.hexDecode("23")))
            .setE(ByteString.copyFrom(TestUtil.hexDecode("03")))
            .build();
    assertThrows(GeneralSecurityException.class, () -> verifyManager.validateKey(invalidKey));
  }

  @Test
  public void createPrimitive() throws Exception {
    if (TestUtil.isTsan()) {
      // factory.createKey is too slow in Tsan.
      return;
    }

    RsaSsaPssKeyFormat keyFormat =
        RsaSsaPssKeyFormat.newBuilder()
            .setParams(
                RsaSsaPssParams.newBuilder()
                    .setSigHash(HashType.SHA256)
                    .setMgf1Hash(HashType.SHA256)
                    .setSaltLength(32))
            .setModulusSizeInBits(3072)
            .setPublicExponent(ByteString.copyFrom(RSAKeyGenParameterSpec.F4.toByteArray()))
            .build();
    RsaSsaPssPrivateKey privateKey = factory.createKey(keyFormat);
    RsaSsaPssPublicKey publicKey = signManager.getPublicKey(privateKey);

    PublicKeySign signer = signManager.getPrimitive(privateKey, PublicKeySign.class);
    PublicKeyVerify verifier = verifyManager.getPrimitive(publicKey, PublicKeyVerify.class);

    byte[] message = Random.randBytes(135);
    verifier.verify(signer.sign(message), message);
  }

  @Test
  public void createPrimitive_anotherKey_throws() throws Exception {
    if (TestUtil.isTsan()) {
      // factory.createKey is too slow in Tsan.
      return;
    }

    RsaSsaPssKeyFormat keyFormat =
        RsaSsaPssKeyFormat.newBuilder()
            .setParams(
                RsaSsaPssParams.newBuilder()
                    .setSigHash(HashType.SHA256)
                    .setMgf1Hash(HashType.SHA256)
                    .setSaltLength(32))
            .setModulusSizeInBits(3072)
            .setPublicExponent(ByteString.copyFrom(RSAKeyGenParameterSpec.F4.toByteArray()))
            .build();
    RsaSsaPssPrivateKey privateKey = factory.createKey(keyFormat);
    // Create a different key.
    RsaSsaPssPublicKey publicKey = signManager.getPublicKey(factory.createKey(keyFormat));

    PublicKeySign signer = signManager.getPrimitive(privateKey, PublicKeySign.class);
    PublicKeyVerify verifier = verifyManager.getPrimitive(publicKey, PublicKeyVerify.class);

    byte[] message = Random.randBytes(135);
    byte[] signature = signer.sign(message);
    assertThrows(GeneralSecurityException.class, () -> verifier.verify(signature, message));
  }

  @Test
  public void testNistTestVector() throws Exception {
    for (NistTestVector t : nistTestVectors) {
      PublicKeyVerify verifier =
          verifyManager.getPrimitive(t.publicKeyProto, PublicKeyVerify.class);
      try {
        verifier.verify(t.sig, t.msg);
      } catch (GeneralSecurityException e) {
        fail("Valid signature, should not throw exception" + e);
      }
    }
  }
}
