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

package com.google.crypto.tink.hybrid.subtle;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.HybridDecrypt;
import com.google.crypto.tink.HybridEncrypt;
import com.google.crypto.tink.aead.subtle.AesGcmFactory;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.subtle.Random;
import com.google.crypto.tink.testing.TestUtil;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for RsaKemHybridDecrypt */
@RunWith(JUnit4.class)
public final class RsaKemHybridDecryptTest {
  @Test
  public void decrypt_modifiedCiphertext() throws GeneralSecurityException {
    if (TestUtil.isTsan()) {
      // RsaKem.generateRsaKeyPair is too slow in Tsan.
      return;
    }
    KeyPair keyPair = RsaKem.generateRsaKeyPair(2048);
    String hmacAlgo = "HMACSHA256";
    byte[] salt = Random.randBytes(20);

    RSAPublicKey rsaPublicKey = (RSAPublicKey) keyPair.getPublic();
    HybridEncrypt hybridEncrypt =
        new RsaKemHybridEncrypt(rsaPublicKey, hmacAlgo, salt, new AesGcmFactory(16));

    RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) keyPair.getPrivate();
    HybridDecrypt hybridDecrypt =
        new RsaKemHybridDecrypt(rsaPrivateKey, hmacAlgo, salt, new AesGcmFactory(16));

    byte[] plaintext = Random.randBytes(20);
    byte[] context = Random.randBytes(20);
    byte[] ciphertext = hybridEncrypt.encrypt(plaintext, context);

    // Modifies ciphertext and makes sure that the decryption failed. This test implicitly checks
    // the modification of public key and the raw ciphertext.
    for (TestUtil.BytesMutation mutation : TestUtil.generateMutations(ciphertext)) {
      assertThrows(
          GeneralSecurityException.class, () -> hybridDecrypt.decrypt(mutation.value, context));
    }
  }

  @Test
  public void decrypt_modifiedContext() throws GeneralSecurityException {
    if (TestUtil.isTsan()) {
      // RsaKem.generateRsaKeyPair is too slow in Tsan.
      return;
    }
    KeyPair keyPair = RsaKem.generateRsaKeyPair(2048);
    String hmacAlgo = "HMACSHA256";
    byte[] salt = Random.randBytes(20);

    RSAPublicKey rsaPublicKey = (RSAPublicKey) keyPair.getPublic();
    HybridEncrypt hybridEncrypt =
        new RsaKemHybridEncrypt(rsaPublicKey, hmacAlgo, salt, new AesGcmFactory(16));

    RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) keyPair.getPrivate();
    HybridDecrypt hybridDecrypt =
        new RsaKemHybridDecrypt(rsaPrivateKey, hmacAlgo, salt, new AesGcmFactory(16));

    byte[] plaintext = Random.randBytes(20);
    byte[] context = Random.randBytes(20);
    byte[] ciphertext = hybridEncrypt.encrypt(plaintext, context);

    // Modifies context and makes sure that the decryption failed.
    for (TestUtil.BytesMutation mutation : TestUtil.generateMutations(context)) {
      assertThrows(
          GeneralSecurityException.class, () -> hybridDecrypt.decrypt(ciphertext, mutation.value));
    }
  }

  @Test
  public void decrypt_modifiedSalt() throws GeneralSecurityException {
    if (TestUtil.isTsan()) {
      // RsaKem.generateRsaKeyPair is too slow in Tsan.
      return;
    }
    KeyPair keyPair = RsaKem.generateRsaKeyPair(2048);
    String hmacAlgo = "HMACSHA256";
    byte[] salt = Random.randBytes(20);

    RSAPublicKey rsaPublicKey = (RSAPublicKey) keyPair.getPublic();
    HybridEncrypt hybridEncrypt =
        new RsaKemHybridEncrypt(rsaPublicKey, hmacAlgo, salt, new AesGcmFactory(16));

    byte[] plaintext = Random.randBytes(20);
    byte[] context = Random.randBytes(20);
    byte[] ciphertext = hybridEncrypt.encrypt(plaintext, context);

    RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) keyPair.getPrivate();
    // We exclude tests that modify the length of the salt, since the salt has fixed length and
    // modifying the length may not be detected.
    for (int bytes = 0; bytes < salt.length; bytes++) {
      for (int bit = 0; bit < 8; bit++) {
        byte[] modifiedSalt = Arrays.copyOf(salt, salt.length);
        modifiedSalt[bytes] ^= (byte) (1 << bit);
        HybridDecrypt hybridDecrypt =
            new RsaKemHybridDecrypt(rsaPrivateKey, hmacAlgo, modifiedSalt, new AesGcmFactory(16));
        assertThrows(
            GeneralSecurityException.class, () -> hybridDecrypt.decrypt(ciphertext, context));
      }
    }
  }

  @Test
  public void constructor_shortKey() throws GeneralSecurityException {
    if (TestUtil.isTsan()) {
      // RsaKem.generateRsaKeyPair is too slow in Tsan.
      return;
    }
    KeyPair keyPair = RsaKem.generateRsaKeyPair(1024);
    RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) keyPair.getPrivate();

    assertThrows(
        GeneralSecurityException.class,
        () ->
            new RsaKemHybridDecrypt(
                rsaPrivateKey, "HMACSHA256", new byte[0], new AesGcmFactory(16)));
  }

  private static class RsaKemHybridTestVector {
    public RSAPrivateKey privateKey;
    public String hmacAlgo;
    public byte[] salt;
    public byte[] contextInfo;
    int aesGcmKeySizeInBytes;
    String plaintext;
    public byte[] ciphertext;

    public RsaKemHybridTestVector(
        String privateKey,
        String hmacAlgo,
        String salt,
        String contextInfo,
        int aesGcmKeySizeInBytes,
        String plaintext,
        String ciphertext) {
      try {
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(Hex.decode(privateKey));
        this.privateKey = (RSAPrivateKey) kf.generatePrivate(privateKeySpec);
        this.hmacAlgo = hmacAlgo;
        this.salt = Hex.decode(salt);
        this.contextInfo = Hex.decode(contextInfo);
        this.aesGcmKeySizeInBytes = aesGcmKeySizeInBytes;
        this.plaintext = plaintext;
        this.ciphertext = Hex.decode(ciphertext);
      } catch (GeneralSecurityException ex) {
        throw new IllegalArgumentException(ex);
      }
    }
  }

  // I can't find any public test vector.
  private static final RsaKemHybridTestVector[] rsaKemHybridTestVectors = {
    // These are generated by this very implementation, as a mean to verify implementations in other
    // languages.
    new RsaKemHybridTestVector(
        "308204bc020100300d06092a864886f70d0101010500048204a6308204a20201000282010100a071550bcf139d"
            + "2629d6e6612697f23a0a1abbae78658801f146d846c59141c280b8e361251701d2761ef97d5c38756bea"
            + "03dafb12da3e8ba527400b5c7dd823e53e3d6b21ed015e818dfe590033ba24e3d483bcd2f3b7707900b3"
            + "03a7f076236943ddb553be657ee68f19fa9a1ea7ce81a82b87d11ac69e1b01a8ad7b1107bc2f39b8a13c"
            + "2f1fc69f657c2e318bec3cb04c8e26813cef9a3a50189e690031399eab70637b7cd6a7f850a39303053f"
            + "8d16655437080b115e2ce5c6d60568eb6963eb4a8e0887384d1ee889b888effc17a275179c047d533ea6"
            + "70a7cb3286a9a56dbcb00b26cf410732d656db9e5d94511c35ee38f156a0928b36f3be9f47a371020301"
            + "00010282010079ff5344c473cc95dd509c23193e86a05d5890878ce2df3562ea94bfd3b0ad0921e9f473"
            + "c4c926c88aaae8d8cacbdf756c1efc5ed7a9fdcf1f88a5e93dae2f30b43acc66ef0811777419ad62ad85"
            + "a7b02f5143cecbb528322cc03c5eb64f60f5723079a04c8a4510e66dbfba4f80a9e69bae6d533bcc1964"
            + "d5724079914f94c9edc29cebcf0bf26c6101ce232c705af830e0a4e2850ccff0fbb632fccf8b02a79c2c"
            + "6572c88d6990a65227c7a37895f0a0c55907659179c2614db5123bacdb6203775b4ded2661046dbf95e1"
            + "718e582e8b476ce334256e40c236fe2ce625350cfaa787f8fbf68bc78a6d650cd58319d21afd001ed935"
            + "28a95c3c329413e5740102818100d32993fc23e8ac07120ad347c22df45e7cc4373424e9ce131d6452fa"
            + "5d27d5c2f998f713d5d3f5fca03cff5a29876e4884c5403b53f4cdcc08678aadcccfc4805e3255eef4f0"
            + "d95713ccde584b5a021c3dbb57fe51638bd0e9ec2f22cf69d5cea2e98439203b19f35f14b14e8b7b54c8"
            + "8dccfc56fa887b827f1b0233933ecbc102818100c282b8047ca42034c3b59f682291a7fe1d366495c4d2"
            + "b65b81632fd3687c040e81568b0c7e8225e1c5d7e7f63193c1929e826978d37f078b3e36e361d73bb4f0"
            + "1b76065294f713bbca0a6fa955bf3aae110bebefa9ad0749a68d608cb4dd6341db78c79780e6e9e0c736"
            + "3a15ef5ef614ce8bfc1f2e91ae5c602fa7dff8d983b10281807c20fbe20345da2249e3dd31589f65004a"
            + "3d99e9e82d1cbbb5d26cc8ca0c09a794cbebaa584f4251dfec1b7b67e039df1d554a9dd58b99926ffa55"
            + "d63708878da251da9c1e969a5c8ac22a8e22b5657a2e7bbb8d3f50d236dbdbc015a971a082d8d786a782"
            + "1fdbf0699b236375b0e934ffce5923d42078e24c4f972ab44afcc102818057636b5178be344a0073a4fe"
            + "a02958946e837585643c56f99d93f674c0c896f9fd59e876e08f907d72e9a1a996748fcf53afbbbb312a"
            + "2d357dea23165e20d115df0093ae9e86b332f77ee0d3ef564f02cd5dd1ce8728d9d15926c36df4045307"
            + "cf96dff54d50715b2fa5494b7993ec7344a8d7c91a9f10fb27abc17c7acd1ec102818012e5237bde4670"
            + "639136fcf2a8308de2cd952d3256071af387754df91c811c7a63ce8a389689f3e9949580f5f659a60698"
            + "17b6f5849128c56f7bb391b197cb333a926ce2430989c89a9e5de684015d3f4bb32eeebfc5e74101c33d"
            + "5fd25917389a7f0577c3ac378e902ea391fca6f523c5b54518ea53e322cf75920560280b63",
        "HMACSHA256",
        "a19fd193ad1c247422d3",
        "416efa391903a2e93dcfeecf7d5353ffc97f9b7d",
        16,
        "8012627431bbe7a54375d1accb467c1f7c82d1d758f50a2feda4d42cfabd",
        "47c8f7b8d060fe7a6f423c0ee287f5a84a28615403c84d5c113aea0bc9b102e8a77ca7120aba15cea3d7bf13cd"
            + "47f802c8490e02f3209c37ed278b23d2e4230552c0e32f35ca6854c5b3c26082ce2439f311e684f3850b"
            + "91e780b7839cef502e69f02688aaa768517cfb88288e710b6093e87ebe250bef08e861d6cc2925767d5e"
            + "1d9185c5fcc3208bc12281e72155bb7453133b1c78da8962a261e9be0b38a97d6fdc4319d66cf241268c"
            + "b2aaf9fe5905df60db9e3d690b87a2924fe83904b2a21a420d5beecaa61abc5d9438e370886bb8965214"
            + "bd3624e1c30e1635c36043730d17e8bd63849cb2fefe036a911c8240fc6c2bc2d71768938a48b87e321a"
            + "ae063b578bfd88000aa61a85794f4b29b64b8e41216e255fc6221296617a1eb3a66666d610c71fbddfd7"
            + "2911390b05f50d79d0b43ca30e26be996b"),
    new RsaKemHybridTestVector(
        "308204be020100300d06092a864886f70d0101010500048204a8308204a402010002820101009540ff714a59a8"
            + "d4f567da845a5034263946e9fded30c10adff76ad99b10256778baf65b4a05e3e21314e089efb316d559"
            + "6382290847ee422204f092e0f79b76a1c22d0921daa754489ccbd6a1c59d5e2e98b02b25e42e9272a77d"
            + "e716eb4068fc22a86756a67a29f96c6e8f60e972aefd68762d5c91583483bd4875ef85fa6039aae30f1b"
            + "6b27f33a970b04bb399f0aa1c49fcd1880b98402582275e6a75a4f1045d312187019a485ecd3b4eeb0b6"
            + "076ab532f6c14664841e9d01b6750985f6ba2438ffa4641403e9991c4e6afac0f8ea71bd9645eff3a22c"
            + "73f77c2d189faa029f06ed5181589e4daacb566229e4dc55fc7c05f33ad93f39de55a85f50d6d9020301"
            + "00010282010039cb265e96fcaadc737e58660196a6eada28f47867fd05f311107c2670ddcaae0b58d206"
            + "3d5e948439014f84f9f52df5451cbc0ce970f8f850b5faf5d4f8ec10fec7f2aa639a884aa1a75d62e9d7"
            + "5c7d58abb523b013705932de5a693e3daffe370bb08bfb48916b6972ac4906acbec4b5c95a616c43b794"
            + "f6223849ba8af58ced7eae465f20b517ba91b1bbff2f5ae85810885394a9a1435f363c9b29fece9edec8"
            + "8764af6a05256773a87bc92bd5a017481bea52398f0b0371db4d659e97527ccf6983d81d746da3964fd3"
            + "5fed63d4ab9c006055c579706940d9f015c6cd7a0c93c827f026c0ad4a59095417da61d80f07b6bacf91"
            + "a11b6ac51221a94cef2502818100e873d0c21ff9c5ca8e8bb8b848f6a963c1111b639d7c0bf710344c31"
            + "318b2282c559f0c874c9462415ca4b15ad89d4f90c69b4cfd3ac4a9e2064f4dde2e9cc44222c944221ea"
            + "7050c7d0f9f01e716a2e2d8755064dd7b78e9b557a9124671f0087c25bf7ce0490ffc6b4da2460bd9676"
            + "ab169b97ec31967abd2b243378d678bb02818100a45f98c819c4298d2928ed23f97efdd8a439c5d741c4"
            + "7827ca39e93d58eadca31c213ca715cf1c8b321d3010f55afc2c4f620c1ab341412a2c0caa2f1af9e57d"
            + "0168267a5401e411cbe24ee114a6eb4b815708ea74b3b78b07d49f639641f55997efdb8e1eb1475f2513"
            + "23c64e3a33ec0f3bf8120b111f5e639384ac99e7af7b02818100e6e191ea1ee471a69d2afe505c78530a"
            + "f7cacc0f876e9c5bcb46869f1dfc7a4cb5447e3a3c75662b9551167ef39d41621508314573935f91ebcf"
            + "1ac0011003897100224a0571dc19003efae19afb3f619a6b1ef26202ef18c00488f6fcd7481db8ba3daa"
            + "c680169d567a6f694e85409ba19794f7b2ec15f0d74fb06747908edd0281806f751f2d38438a855c8e92"
            + "d69cfc5e76c34d257903f08c2536fc33cad47b552709110486abc427afbf48896a4664eeafc11853eada"
            + "f7f98ef6159464a29f26dcafd2869cd64ffded8f59a270ff46fc2fd3c1479b6b8cdd7d59cef4515bf6d7"
            + "be6bc74a12417fa64cbee00e970e3e6b2cbb5bc7a7bc775cd4ed227f896646f2f702818100b1c5021466"
            + "a2fa1a2c3fc686a2595e2f04ac7124c4a9134146f30120029046bd20839074fab913e09fccb8debdba4b"
            + "68d788a8e2aa10041603b875237569c759c628bb722c3c73d1fd27373344ecae1d7d4ed186fc7adbc84d"
            + "f87275564fed44f160eceef0b2180152ddd581b483d8d87f7155fec2ca563594d413fb7c4fac99",
        "HMACSHA256",
        "",
        "dbe8324084cef0bd79b1e371573f81a455eba51d",
        16,
        "c1ce9e69a387d0f6bc50e0644528726ad6415708582f42977afd352d5493",
        "39f8503afcb5ab22ee8787cfbc8fbe0462b2a9449389e1c7a042f80505e5260388ee0cd5c33c6b586475d1b078"
            + "bd6e50e12c85c5e88fc02fe1604dc1182f9afb7066daf04e34cc02747163acada9ec80da24044b3be84c"
            + "624acb0a8fc8f1cea11d307eb5ec51aa46c1e79ec6c5afad8bfafa3d26495a7acb2652a914531541e270"
            + "d82e93c91806fb353b20dc62236a3f949c01849e286a7d0f892247dfcf301d5e107f33d1c9627565aa8e"
            + "28d9b9cc49fe430d69294813bd87d940b9f8fbf98cb9fe5de09e0c763ea2eb9cae4c678b71ab21d861f9"
            + "821a7ce9d1453bebc702945862edcb25d9db71ea3abf711a069443602005d8abdf9289b80d1512e356f1"
            + "f6f5fd5673833a615cacec69814ab293530733fa1aadcf76fe8c10595858f5ef744d509fd972b914bc0e"
            + "537f44b3e463d3063299637d5604c56b30"),
    // These are generated by an independent implementation in cr/309235397.
    new RsaKemHybridTestVector(
        "30820943020100300d06092a864886f70d01010105000482092d3082092902010002820201009765065f3e44a8"
            + "1f63a771e53dd3ce7fb50830a82e06853c258a8f3761774083b40c967203439becdd10bc9c40c3a7c408"
            + "113be9bc845b5a8c943b48b9076245990a480e8a4a6cc2ada41a027194b2f80db2056bc78fbf0cac1560"
            + "93d3442fd981863d50e668f11c0f33f34d5c2b20753ff800952e5c358b1ab46885021c38ccbed1f31a2c"
            + "53ec641e2b36ff1c049885fdd0c5d02cb1ba2ddd46751f868b0f4a0f06be76c2d81a7579f60d73486e35"
            + "c9618ddd20243b1cdc367e3c178d001a139b0c7131b789beb214fff2628a66ce5a3a9cf046f0f41bd259"
            + "34da45b0f0761dbbf5a5c43aa017f08515e4d9e409d9609778fc9f2ae855f01b99c8c867f9293cc82d6c"
            + "d24b11466185f5d7ff3d25d9ce41835fa8c8381e2c86a2ad7efb52b97aee0401561b3980eecd5ae37b99"
            + "768dd40cb7fe327992e84b8b730107bb0f6d983c053701b0abfaa51496ac9069032229f9b0c5e76eb829"
            + "a5b1ed13f7dbc71abb0ab58b442d499fe15a91a48fea210930fde25193cc5fc6d3221861d70553afbc6d"
            + "b801b35e1acd11437358a76b20f16999ad3db75a70c92c539932ea91c66713d1242a4ab770f53a05de10"
            + "a76052a5dd7bacb4ebb8abf764ee5cbf355c5634543c66b96eedeba52dc9b494a4de2b061b6ad5ada7ab"
            + "60599a2010f910bd42c84560c69f53300d55e417206044a779c82d4dabcd1a48b3abbd46ce7645a29771"
            + "570203010001028202000a8fc5ae074e0adc85bb3cbadd61555a9b6a82da78bb83b7fa767c1f44f168d2"
            + "c750c97e12b438c0817b956ce127c5206bdfa7ea5a78715713cf938333454c99c65f6d3f766e52c01215"
            + "0cab76f904b3416155f77ae8904f7601d7c6f84a1d7c7308c6664a6cafc5615a22731726fb10b2f1be38"
            + "aa0f4cbcf393fa66ad0b02fb65a487ed1f828b4f40bb8b0ea909b90a3ff6bc96154820d0ea4aec08d2fe"
            + "0887061d56543aab90ccf9412d1709ca867e120c2f8cfa7a153d579fded955c0d810de1434215fc88041"
            + "342dd6df0100c30c90623a70f8864f1a91969a539a506c2d0edbc840b4464ee53ca3965f8d0512e12630"
            + "0e8f9c12b14c1ae0d39d0783de587f8bc6e4ce6ce7f62a579f7de54efada511d4c37362ba28d9a4a95da"
            + "25891e5f499a3b89c007e18e73e08dc4db23380c564994888a437afb5ece1f1f153053b07c6cb233032d"
            + "c0033f4305eca759751332b4a499bce738912884c3bd926b1cdc4a5c5bd70b3a1fb4d235050b056d36ac"
            + "9354834da61cd0b9005c3b216fd3adfd1139593c4bfb91d5cd94c866b4d3fab126f13f06e25b2894cecd"
            + "192db9220da70ffb47e3745e53e2356e18e10a4faeb788d6574bc202ada02d7392accca1c00c94b36adf"
            + "53b2dba6e610f367f6c7782d61e2a96f835ef7e9fce6012fb8c73863c88139736216535a43ecec6580b5"
            + "dda2d0cf69593128e32a62cdcd65e25623810282010100dbd85e276c5cc0f46026b3199cd27581846f69"
            + "29e4ca796633343e8f69c176498b4fe3993c6f48ff9c4310ef1e24a7a1a7481580d39a0212c4cd066ad5"
            + "d6e609d57eaffcda723154c6cc2254b7ba135d019f7cc6b044083c55e6e26f42655f3d65803d928d3b56"
            + "7ec8526f69ac5e526f42b8d4f2c4bdf6176c89a835c55820a06980b1681b2a645aebe1f322106ca265b2"
            + "4148f15805c2b13432125eb9319e7e36c724262d7b1e2d34fca67759acce9c07a5e6d1c96fb7759e22a8"
            + "89bf61afc34da81f8348b1b45c7acb8c23557f00fc1ade95989c72fe19fb759244a1c819d49b06ee6855"
            + "ae44f5bd6727aadc79cb9020e1103eea378fe4b676bc7d47b487b10282010100b04ad789a5f1c180ba6d"
            + "2a6946e971aa5c57f9d3a3e2843abe7abe67a6e2cb1f0572345c23753e85d83b57825a2af9426435be05"
            + "41db0a91d1176cc56abdbe62458911732d8838cbc0c921355998189e65269a128cad9be72bc3361b2e0f"
            + "933591e9079fc27b6bb63acb74c150c8fabe7bb78fc50291152abd1a831c7e2f31e52ffab417e7578eef"
            + "437d5a207f8263c8030f586f07e72a517f9aa44ecbd3c9a44b2b8890b3f79e2192600dbc471c7d09eee1"
            + "d79d553aed21163b6ce0f50eaf36da964f687a5349302d1954284549c1360ac160f3b045a4763e23e861"
            + "62fc4bb983658b7ae494111f3780506e0e736cc929156c6acb715703e7750e037f9dd3870282010100ba"
            + "4beffd9866415cd4ddf6878dcd0aa66683c2aa2da72698e46b31587655ead707a6fb47af5ede8d3cedd8"
            + "3bc95f666e26437f755bdaf646d15eac417c544f3ba61f6522f03a347392c30994a0dc9dec02a414288a"
            + "d61be48526d25b55f8716ca5c6b666aa27ce74416d19dc82a4ab567d4403b075e843d235b7b1435fa7fe"
            + "7df0e98d6c9b18a1522af19e070fc3ff1a0ea4241be06b814088eaa5867f88fcb617d5495cd0cdb414bb"
            + "021e4ea53f3b161da508a45dfebd887e2900893a149dccf2d1b5629b077bbfa28f3a81f6c1592449e0b5"
            + "044e0f6424c0623140d797a9cbf0533f544ac712c8eb67aec5ab6fca80a85c10584042353dab219338d6"
            + "bab50102820101009a8a9155f665eef694f6dbc5fc46eac0a840eb1dafbe03a2a7965c51eb07477ec33c"
            + "71501039587ce6a866b73baa0e663808b0b2551fdaad2739bcbd772c2cb863329c5c769ec30342d64e49"
            + "416846b49c0171f12ee78612e9d730183591abbfbb5027c1d23075a502f7963b5d41422637b81bcd5dc9"
            + "a75f96f4a5d91578f3e970dcfa8135e918c1004de3f337342b9a8bac291ef4339e72614544225b2626ce"
            + "e2a2a00e11e5d0f6a7259304e8e5bd6b36c13e4d8b08a4156c32dde87a8acbe86f48730628add82be66d"
            + "1ccc4ca93239d8c5dae2e534b7ce7bfce85a6ef6b2bf46c37eb955a5c338b563c39e2706e267999f5132"
            + "7173c30f06192416c709a9030282010056c8258f69c9e0fd3d58536d95fbcb074dbf2b90c8fc7e66c338"
            + "54c7476d60665204cc67fa1a37cc30427a3d70c759058bcd9cf8528009d4bda6ce2f12320013a3df8238"
            + "59f70afe736ac0771bfe9afdbf8f531c9904fe4ea072f6726c04f51ab947539106c058bbe7afc9bb6530"
            + "37cb2591503216958e32a143b2a4bf578b8fc495babe031f4ca4ad0a424997828a4b19883ce165335fb7"
            + "675db88bc79315cecab0a73c778a5f8bc3ef068eef0e5902bc5d3e5aa0947f5acb5e0376699a5ff50ee8"
            + "9cca30ac7e855cf17cbccdca0e54ca928c5f35fe12d43aaa21b34009ff90961c07e929eec10d8e22bed4"
            + "7f44eb45f85f7dd52b811ae4aa23f1beb96714ee",
        "HMACSHA256",
        "2a9226902d4a4c91a3a0b566a7de001e",
        "73696d706c6520617320646f207265206d69",
        32,
        "6162632c2065617379206173203132332e",
        "3e6060a0c1f06e7475ae58d78510cce4ca84ba64705b6195991106818745db0dde5826e789b11ac9e230ff146f"
            + "7b8e72ff48a6e92adb23036eee424b2af26f6059d315a963bac676ee7827a9c7ea75b42aef28d06d50a8"
            + "58cfb0f54d663e2c87134201f5fbf67af80a0b185faf721a894e8d43f401fe882a688a0a91cbdd13409f"
            + "0deeeb86c170a46134372d206581b0f46faaf1ce8b0c30cef83b7d8296c9af37380c95bffa0a832e97dd"
            + "9f6d4545539893b342665c795fe75744fb0661a73a853ced4ef472857292b6e27aa5729def89b4d53fb8"
            + "3f0a2825186b80ceecfdebadb2190e6dde117e41d1f365637edf0ee5872e834908a9dbe1cf06131bd994"
            + "b26c5306a426dd9d621ab972bf5584b3feadf8ab1b0b95ea32ecb3bcb1a51738cf4aae5abe92f34e874b"
            + "93f07494fa16ed956d4023f68d8b34418136270417134a3ec5372a6ac7df61b2caeecb5101b390b43964"
            + "a78006127a4c26b05679ba42fbf206862ad85355c12438c5c7143de914974cda72f0e8b752b9e7d4b8ce"
            + "d1034038291fc02f30bfa630fb10f4c35d09fc2231adf3594be02f248b2e28dcc7a5382c1129dd86ea58"
            + "1eb2c5abbe06724e762cae49e069c730bb9dda76df7beb99483e55383ae95fcc90772a7a23f5ee556580"
            + "35a7d1fd812614e6e688039150e8af6afff12e9a8503d530dd1cec8d25b81a59b3a0ba0d7d2e48179bb3"
            + "756256829f93bf1804641f5d620810037843f17e4009c30957ef91406b1daffd68275e6856903896cfc7"
            + "749db8814299904a")
  };

  @Test
  public void decryptWithTestVectors() throws GeneralSecurityException {
    for (RsaKemHybridTestVector vector : rsaKemHybridTestVectors) {
      String hmacAlgo = vector.hmacAlgo;
      byte[] salt = vector.salt;
      RSAPrivateKey rsaPrivateKey = vector.privateKey;
      HybridDecrypt hybridDecrypt =
          new RsaKemHybridDecrypt(
              rsaPrivateKey, hmacAlgo, salt, new AesGcmFactory(vector.aesGcmKeySizeInBytes));
      byte[] plaintext = hybridDecrypt.decrypt(vector.ciphertext, vector.contextInfo);
      assertThat(Hex.encode(plaintext)).isEqualTo(vector.plaintext);
    }
  }
}
