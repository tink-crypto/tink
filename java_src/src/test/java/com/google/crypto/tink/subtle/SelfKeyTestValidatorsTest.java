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

package com.google.crypto.tink.subtle;

import static org.junit.Assert.assertThrows;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

/** Unit tests for {@link SelfKeyTestValidators}. */
@RunWith(Theories.class)
public class SelfKeyTestValidatorsTest {

  private RSAPublicKey publicRsaKey;
  private RSAPrivateCrtKey privateRsaKey;
  private ECPrivateKey privateEcdsaKey;
  private ECPublicKey publicEcdsaKey;

  // These are keys only used for testing, generated with openssl CLI.
  // openssl genrsa -out private-key4096.pem 4096
  // openssl rsa -in private-key4096.pem -text -noout
  private static final String[] RSAKEY_2048 = {
    // N
    "00a5af78921b98763aa4578fd75b7aeb13f7bd7694e5fcf0e25d0c01424374d5cf1c2429c2d94ec1aea4782c0b34dfc63165daabd2573aa90ef6ef5176c985af467d06e68bfb24632f353e650895205777c368fe01593a705d0d300c90b7b7fe09c5012eb07cec76726567f5dfa3c0e73e7d50524e15cc7fac9c47c5d94729b56f0a604485a426716d9e29f43d1c08e4967878ae230f074a97a4e8d17d37dfc6ced5c59485a0640b3b1b6c77816c9123490e49813f43847588689d4c4989d653a92069a8bac5c4fa13abc95b3a27bb0a1a5097e97fd4dd3575656a057715c2a7f3a70058f8f6e7f1ca957cf45f1b748a0f8c2ccd2a51cda862ee25e9346daedd67",
    // D
    "6e512b427d45425341615bd0d4843f4988468a5211e01cb35ba8c69dcc345ab80fd0b44d9c4b28029457bf5ba6d4e82db3d7a957dfe49af3efcee0baeaeb2c0d0eea2d4f3ee4b7759349fc137ed78de59c22a81d55bfe758cd93148ab708b708e2372b532f9a723330f9cb6820ac2c4c1b3c03d1220a8b67ee968b5164648cfc53f68b8672aee8177c7d75f7782349ee5396ae796111740a56f797e2bfb2aa3893bd0cb84f375842977578458ca0cd7c8eada0549ed7a7dce08088d89f4d364aae77dc2e3f752f8056947c5f347a480bd3f9bf64b9ae0b6d20dc87a40da3d7a330c64dc9583411deab6aaa846ca719559ae2fb9e2b136ee711f94adc2aaf4421",
    // P
    "00ce36c71ab928dcef3783fce65dca82b68a9d2cae54d27f8fcd37c0e636bb1e86fbbba6f2ef4f9ede77563353e80fd4ecc853797d6abc5c09b52a5ad4ac239213c5d385c4548f68cb086146b7e3aafc0ea636f9a9b20d6eadcba0947224a6114e4f1b03f058717d00bc6a6db470b105c1a55a38bbf3d43cf7d6fc361d044defa5",
    // Q
    "00cdafcb345832874a952d730cf97536558f41b117e5284d5de6befcc5248be076fc326ddbbe9343c6bc7dfdce72b413735d1c2b75e9b31ab64ab546ae6dea32f3d3b51ee9fbc2cc152fcdd0aaffd5f8a7a64f451fbec7947ebc03eaff2354d4beaf651e1f8ed3536d0d6b4a32a991d96a1b8694549baec88b2a1f3a7c97788b1b",
    // dP
    "5ddd333de7c040e8a6656ecd512de7d7bd3a93e6fa7722574b7b3053d9dfcca2769d50fdcd8e796b1bf8e1be34a8582c3b773b9aa9e5f922f612c46b7fbb653798d9924eee8aa4919e4be10bbd16cc4ac2bfcd5ebfcc3b6fe27b4276be55d514c70f2df8cdd942a3fe1f97b605819e742996eab22ae795a4de77c90de632af7d",
    // dQ
    "00a0e28671952340cbc7cfdb1424f3d7e228c1db81b34f48e4d01e479cf4af2c8e254a54bff35b41426c21a8ab18f15ddd78d115f58f2cf711eb71cbad986ffe16d65befa859b2ceeb2b8f334eedfa321b006d34c655f5ca632f316958d40c00b47e80fb84f7b4b8a6ae3e63b52909da23b3101b69eab4564cf44fa4f1db91004d",
    // crt
    "008ca975a95b86bb7e98e58dccb8b7f26d80cd47e389e898f0dc7281f97283981ad748be97ba335ea867ea126197f9f4df1ea33bc383375ce13b08d346ba54f11ccaa71f3314451db255275f090a88a266007b1ea27b762d2ba37e454e7c4f13d798af6f537348b583b13ddfbfd90997d118df8d5d9c369ec28230c415a71c1bf3",
  };

  private static final String[] RSAKEY_3072 = {
    // N
    "00d3764ebdb48112dfefee52feaad8c89f6b8be358780f77808838ed8565099c0c3c0217543ca8cacd4d9de52c6c1264f3ca3c648671e8b336e9560ea28f7830b775402d8224f3c8b5645958d389dcef47f35c20a65c0a2ece6b68bdcbfabb30a92ba2b59b5022ba50accc16113d6d30053bb079685169c454a93f492d6f17d4c7e770b20e7175577284f3505789d127013ada0c44aac2167c47d8a4de377ab9408cf7d5319218ed666b317d459c829133e70906d05bb3138bc593ce7b025705aae3244bb634eaa70047204ed8b13c9ce9fbc4fa0277afe5831897cc838c7fe92a8eaadc1961a70c95254b363efea78dfcdba9683b4105c2e19384fdec569d6c04c89e7f3eac198c05c906e523e5a63e047f45295f3fa7ec3801b7f1d52064218551052753973f184ff85a5e8938ac621adfcbcffe8f3cb936263b026a2e09fcd88510dc37f31d3acf49046d3ea44c453414c70c0cae341411825fc38edfe4d6743dfaafa0b1b4a2f37775c7c75c40f76f1bf01e9be123820da1e34c59e4700fdf",
    // D
    "00b6c2efb72204d48d5b4f3dc8015d2fb82939541aa859a5cd1eef24ca3fd3185db297941627ff32985256ff356f8a4e5a2e161843e2bb5df93d9e3533e68fd87b17098acb8aa87075e5ef1ac869c4dbc1f1e1540eb449d0be7332a9a75c62e0e1b5670152e4e5bee5ef12cc97c5e152b993272927320619bb9a33aa496c54ca80a3d550ef0ebc7e01ea4a68cbdfbf36d8e7468187ef95a3dd723319fb3d34025c79f9d0f6f0f03e6e6082fb6468aaa858957bc5b9db2760e352b636a53616843be5b7e3d30303f6c6cc9717c490bbb178cb0f6ef5e741acbd684f2d3743138de5bf14b95df8005bb312a0ae24b9182df6ae0b119f812f6b708f6edb4eac9f81621511ad10a07c006db7e0c4da38c947fe75704d21b3e3439ae478116d1af6b58c02cc9d12c92186069f5261e3da5bebb63919734851d24a102006672036f1698361f8d6ce674da3f627740c0ad410ddee5207e29d531316d16bcdc33a54e9ad767c68ab72f1abdca33ecc2062cc0a9fd6f8664cc62fb8ad07d9ae840f7ba8d281",
    // P
    "00ea1c453458fdc7e8569b5a44eec1ac99b9a559184cb0423d80e0f7651216dc1453ecd6eb1608b8673367758e20fa73d1586e539598dc8354e30d04672e0a1124281b741c7fa63cc589bcd91be7dff264765d20e6757ad3542b522246211bbab38c81480a14240db0fb4055e4caf704672f7bc23a19f3a7365ed0ca252cce29e5b09e60477756025d3ebd0af051fa3ab30a9626251473cb0fc2ed471403ac2e0658a8a67ebf152bfb1a83d752fe42883a5805b95eead77de7d0bb0b48dc1f2b61",
    // Q
    "00e73bebf479037d11942a81da53a18909c24a2d16cb2cf5e2b08f75b2efe8589f2dab5ecae97372b520049907899925da93491c6d624f925df87ca0653dc593b0dc96733a56685e33ff6824f2a90d5969402694fc93bcd0709ae5abcfea491868edd94431dd5574f096b80663f5ab2470100583bafae43aac7db988a96298cefa0ba615e87277b4a9d9dad33cf4eb643d7b14bcea54f3a0e497f0c025ac8571c951b211af7a9afd295bb5a46be2ed6a00588178c9ac6ca9997190d48602aa433f",
    // dP
    "00866af6fd487f6651abb0855300f768dfd6ecee4bfa74558434c476a7ac8c3d8eda65293d4fa87020a92e251c1729566883eaccc91f3cb5977eca5195e0a45d15328618d3e8230dcfa9f7297d51548f3b498ecd3e25840164d97ece390ff778ea70a92630cb41ac2ecb04348d2a504c51e6bc9b577ae120482286a51a55308673e045ff27e98813d1701d60f37d4e3c77e28335a1a2ad9d910e2de8dac00513640771c62f0e0ddcf3cf5495c48c42ad2f3aad06b34e09aebbf46800e1b3a99de1",
    // dQ
    "301482947bd120e155d89cd583cc33cd66abbbc2608ec1b5d8168c579f90c5549bcf654f75c93e91b0cda3f030493ad8bf0555b6dcd944caeb4f269ec6805d9c49d1b2b5ef9f95eee3ed88b938338162e426e195bf366474f59049f05a7bc66a9302392ed121e2c5dfe0f5db350ad7f1c1331457fdb1150e26ba3c53542007f17018a1b78a8d9f702dcf555af866359a9f0c09d803c000b5676e74d5a090c2bf24908d22dab07d716b1352d3e8048ba4f4c23f165816e410f6cf319187de554b",
    // crt
    "00abe67e2e70a261aa1f489bcb6237f06f7d9c650f40bdc60570ec624d1914300339c2fe4dbc14b03e839007e09fc52c060bf94179e87e505b993ceff03e67c542769e035a8f7607ad88b65214fd4c702c7a4e469be64b5562e5ce8ffda2ce2b720ade8b9ea6c750678239f3c136fee1970d3c88db26cdec535b6376237f09ce1ab655822f6f78ce98b869116711a002fbb6046c2ec192224600d06b6eb46a5912353f61860d1ed5cd2d01b4fc7d17a4a7771137b427868100ef2b417fc003341b",
  };

  private static final String[] RSAKEY_4096 = {
    // N
    "00b81c5e5753c233a3cdf8a1d928122b2f2c489af9e05167f481b1dd420ddf4eb57dc2da0541ff2403ec5302c4c44edaac046de4b94658146f4705ca60ce8de9f58eb4b0c660062c16c0600a3e5988c09d0aaf4607a62cae34ffd88db9bb1d1110c01a0117db0b233eeaa66621638fcfff548a778fec609b5adfa336f51eb1c63128affee1cfd4657bb6aac4fe3b08f642e2dc49cf4138f6335a230994ab12522c6d4e909f0f44cd430f0cc95b8d05dc89ded0a0dd1ba83206ed37d1223efaddc4b7ae373f05af1e00d2edde29e30f5152e270d2f50eb305b90d4c8825d6901fdbaf7df561a017a9a49221cba49a51efb88ebfe2639183eeae81f40a008cb9eb9045fb402863a82f7d41a691098d4d9cb8dcd44001b1956727f5f515cd1fb718d3c70fa70ebd5a92a6e2f1fd53d0abfa2c840fdf2f34a43ba6f7ab58d8e055e5684a631c08773d5b85469ca3d7d3137f358ff483e1d99c97d62d7a620488cd2bd963a3e97c5385123ed41f781c57a8456f32c80f096dcf8b823a18a289853d2b19411dded7d91c59380b883907c63e8f3fc75c2836ed6c4dfe04a8f919342b63278c8b5285e4706fda095f5a3286aa70e5cdd074f99358c98f53a9921270b44114824b9d89de39a0cffb6d496589798b55a629350422a84f2acf59a94e02d280beb75d439da4264791c7ef5efcd7bb5c4a8f129fce3c61a47e8601af9799490dc5",
    // D
    "58b32228846beda11f5c87ed2d470393288c9a4d846af3e07293947b7c5f77762ceeb1471332aed14d0bf92b7f40564dc59c843356d69c91b7efec3e9384ff90947e2d2485a2b39f0a73babbab3b1d410ba2c1e47184d9312389db4dfdfdd4f8f2f4144ebff32fb9e226e4d1753c160377617694da56f8c1e138ab03911428de0a323063ee52efc99889d17a824aa10a3c6dd1098eecb880a90e745131d213d0dfa098406984c637668acc7fd5035beaf8741eec27a4f2e52f6852d362f04de3b672b29f2447e7f691a893fe2e2c750baf9897aa04b8ef2ae66356bc9410bfa88175f7c05ef6c77e48010c31733fc2747221b41a304315bcf152f776a855f24caf9e180bc62889747a3adcf450cbe739addf9975aa1b4536360f8f08d312d92a32cbc62e416c173c2140404302c7a59c6f842da8dcb85be07485c39f4a417f91d797dea5b43ef28948bd1c8f8b13a5923fb77e1f01814f9c7b0b2aba0634116dbdf9e74cf50cd73fd61dbd25e6de60b89be0d0d4bb19f6eef21d4c787d6760a87b161b88c05a0ce1098afaf8e93c313d7dfcb35a9c64746703b235e707ee1ebeef6cca1bbd08bbce24aa03b551e0c07e9e53c9079b9aad7e58e2d755ea28ee414d713b78b55c4f7c9c900b0debc29ffaf6002670bc6bce850ae7736c5dd3aedf5a305b0ba23167811e2fd11708115e7cff41f620a117803a110cc40303fa13c9",
    // P
    "00ef3538945cf94c1c402ca845e550b609e53de60baaaf82f19878d910e2239eb6dd6892dba589387f12c4c022ed7585a6a97045e7b7b83bbd9392b30cd06085b5d3d1c07ae60d01c5dfbbe9e82089b50038e9ba9ea0cd59feb05ca3db0ea68a77f212adaedf462ac16d3aeb27af888e8ff00f02da3c6d0da2e6e6a20998ac68788d18cdf5bb0a4632cc44a2473b1ea396115472fe65ea8b64e02a1ec834b0cb0c750048b440dda111466d8e3c45b13c2aa002c35fff467c31722bdcb99d452621d25300d6e3e086f4f51a6508e052b8e2ebe8afeace36bfd668a4ae08ce40a661767318c7c2d63a6aa5fb868ce73cc54d07db95975596679de4c97c5017864437",
    // Q
    "00c50900fee3163808a5e4f0cc3c8605b95a4449ccbeae5fb3507b66bf5e8bacdc320a6082e0dc002bfe31bc1a3595826b50d0e2ae19548e05605940219a20a7c832ffa3cc54e072d913d5489927ff12f4202324cc12198476acb66ef014e5f2c0e0fd4d532efd46b4377b231e1ab81d4cbecfb62dd4d1a28fbec4fa56e1fa429eebe9402d922327e5d13d3a632bb7bef554f9fe9e93ef914e671dda4a450d4708bbf545b74fb37dfd5884b9ca11a384ae373ce42653b97ec4a76991046d275497f220a86c76ed252263eec7413785c8c96f1941f968f7eee62fc379d20bd9ed47a113c46a8560621a84e911591d4365b93a9ea1c362cfd5197098fbf8002377e3",
    // dP
    "009d5b7d64dbe48354f2426e4fcc9253ae1ec7a1557b6b09d0b4648b26b81c8683f5129dc930141cbe3b3282d2773320408aa5f8d67ddd0c2fa1ac976c8e87706e34717f1559d0a4a1ee944743146482552b1b565093a782d4306040ca11d12cb5cae0ceb082e03db01092f9ae99a253660c9d535b0cf5104b6169c69e5978d120bc70dccc11c6a8773238d427d7944838a81dcda7dc93762f5de757688c80e091c945ee8de53de67edebda31bb31cec5f7df353630b22eafffc032ea84bf4f928b69b33aa292dc299d1c31343cb8d9f62679e225b6c5c47c65c00391c41d1f5a197b20f5319b0a3ad149369e7b7161b14995eb20163a41575a0d38a9b855e25f1",
    // dQ
    "0186374ec17cfb83fd9c8ecc55af87bdce57f6e6319771c016604e042efc0fa34873d219511a029a548617f96feeaf2a9b5e72527c79adfb96aa3a17c8747637d3452d0438a7dfdb940eb35813fa2230674b3e4ea1d936b02057ecf5c8839ae429196c8eb72f586bae7e32605a3e9063769a6ec35e011d2bd582fa98cf78bb293594015e18e252bdb167b2daef8ca55a8a84c096837877fc4e49e9d567415a0a5441ea7f278bb0eed3cf7b0c782476b34e541743c0a40fb9ffbd8e54a56f87750177853609997e0f0d0cdcd7c15134a3724b94ba1438cecd5313450efdee7aaa72318ff46f01b6e093a4a5f0b58c3eee36e8e1417cb334e7d47a2a80d9a76c97",
    // crt
    "00b3de05bd6644917afad4817f0609933c8b5cd46f04cfbc21fa0220296d474759b8da325da8061eb4a53f8bc3e1537b2a18c1414ae71f02f527f2d8e4e4b0b5d6feeb1191cb00db5d88a6573b4afdb4fc162eff4d062905e0f7ae50d7277a67c90762422e1604ab371a3319f01d19e7c6574a18163518ade29b4850d9fbc64e49b8586258060593f464b1dc5793412f6faec86a326424ddfae21567249f7e7d3cf4d394d972d9d448773aa7d7856e7bfb7cff16e942b5010ce94932682a78ebb0a58bd067cfe95ef0926a120ecd289758025ddda6a42e1622d7bdf6679756da06687add83423def17a3b0a9815a472354a9b9c82b71223465c04c311d10bbb400",
  };

  // generated with openssl ecparam -genkey -name prime256v1 -out ec256.pem
  // openssl ec -in ec256.pem -text -noout
  // http://tools.ietf.org/html/rfc5480#section-2.2:
  //  04 means there is no compression
  //  03 means there is a compression and select y as positive
  //  02 means there is a compression and select y as negative

  private static final byte[][] ECDSAKEY_256 = {
    // pubX
    {
      (byte) 0x52, (byte) 0x46, (byte) 0x92, (byte) 0x45, (byte) 0x30, (byte) 0x2b, (byte) 0x25,
          (byte) 0x47, (byte) 0x07, (byte) 0xd7, (byte) 0xcd, (byte) 0xe7, (byte) 0x09, (byte) 0x0e,
          (byte) 0x27,
      (byte) 0x9f, (byte) 0x37, (byte) 0x44, (byte) 0x58, (byte) 0x8e, (byte) 0x0d, (byte) 0xd6,
          (byte) 0x8b, (byte) 0xfa, (byte) 0xe0, (byte) 0x46, (byte) 0x81, (byte) 0x8a, (byte) 0x99,
          (byte) 0x3f,
      (byte) 0xee, (byte) 0x02
    },
    // pubY
    {
      (byte) 0xdc, (byte) 0x63, (byte) 0xb3, (byte) 0xfe, (byte) 0x58, (byte) 0xd0, (byte) 0x4b,
          (byte) 0x35, (byte) 0x6c, (byte) 0xa9, (byte) 0x81, (byte) 0x22, (byte) 0x5a, (byte) 0x97,
          (byte) 0xe7,
      (byte) 0xbe, (byte) 0x70, (byte) 0x78, (byte) 0x22, (byte) 0xc5, (byte) 0x2b, (byte) 0x22,
          (byte) 0x13, (byte) 0x3a, (byte) 0x52, (byte) 0x4d, (byte) 0x0a, (byte) 0x7c, (byte) 0xcc,
          (byte) 0xdd,
      (byte) 0x0a, (byte) 0x5d
    },
    // Priv
    {
      (byte) 0x07, (byte) 0x6e, (byte) 0x85, (byte) 0x27, (byte) 0xa1, (byte) 0xb4, (byte) 0x53,
          (byte) 0x03, (byte) 0xdc, (byte) 0x6f, (byte) 0x7f, (byte) 0xb8, (byte) 0xd8, (byte) 0xdc,
          (byte) 0x44,
      (byte) 0x4d, (byte) 0x75, (byte) 0x19, (byte) 0x85, (byte) 0xc7, (byte) 0xe6, (byte) 0x12,
          (byte) 0xbb, (byte) 0x69, (byte) 0x75, (byte) 0x5f, (byte) 0xac, (byte) 0x3e, (byte) 0xe4,
          (byte) 0xa6,
      (byte) 0x24, (byte) 0x71
    }
  };
  private static final byte[][] ECDSAKEY_384 = {
    // pubX
    {
      (byte) 0x70,
      (byte) 0xf0,
      (byte) 0x26,
      (byte) 0xee,
      (byte) 0x16,
      (byte) 0x6b,
      (byte) 0x7f,
      (byte) 0x12,
      (byte) 0xbb,
      (byte) 0x24,
      (byte) 0x04,
      (byte) 0x62,
      (byte) 0x57,
      (byte) 0x2f,
      (byte) 0x39,
      (byte) 0x08,
      (byte) 0xc1,
      (byte) 0x21,
      (byte) 0x36,
      (byte) 0xfa,
      (byte) 0x47,
      (byte) 0x6d,
      (byte) 0x46,
      (byte) 0x87,
      (byte) 0x80,
      (byte) 0x43,
      (byte) 0x9e,
      (byte) 0x16,
      (byte) 0x92,
      (byte) 0x93,
      (byte) 0x6e,
      (byte) 0x5a,
      (byte) 0x39,
      (byte) 0xe0,
      (byte) 0x2d,
      (byte) 0xaa,
      (byte) 0x25,
      (byte) 0x46,
      (byte) 0x1f,
      (byte) 0x04,
      (byte) 0x7d,
      (byte) 0xfc,
      (byte) 0x5b,
      (byte) 0xb2,
      (byte) 0x28,
      (byte) 0xab,
      (byte) 0x72,
      (byte) 0xb8
    },
    // pubY
    {
      (byte) 0x23,
      (byte) 0x44,
      (byte) 0x5f,
      (byte) 0xa0,
      (byte) 0x2d,
      (byte) 0x6a,
      (byte) 0x36,
      (byte) 0xf4,
      (byte) 0x48,
      (byte) 0x4b,
      (byte) 0x9e,
      (byte) 0x72,
      (byte) 0x15,
      (byte) 0x30,
      (byte) 0x30,
      (byte) 0xbe,
      (byte) 0xa5,
      (byte) 0x4e,
      (byte) 0xd1,
      (byte) 0xaa,
      (byte) 0x10,
      (byte) 0x75,
      (byte) 0x09,
      (byte) 0xb0,
      (byte) 0xb0,
      (byte) 0xe7,
      (byte) 0x26,
      (byte) 0x52,
      (byte) 0xf3,
      (byte) 0x6d,
      (byte) 0xec,
      (byte) 0xc2,
      (byte) 0xa6,
      (byte) 0x48,
      (byte) 0xd5,
      (byte) 0x72,
      (byte) 0x6b,
      (byte) 0x51,
      (byte) 0x1e,
      (byte) 0x63,
      (byte) 0x25,
      (byte) 0xd0,
      (byte) 0x16,
      (byte) 0x13,
      (byte) 0xa7,
      (byte) 0xd0,
      (byte) 0x5d,
      (byte) 0x7f
    },
    // Priv
    {
      (byte) 0x7e,
      (byte) 0x1f,
      (byte) 0xd1,
      (byte) 0x8c,
      (byte) 0x54,
      (byte) 0x52,
      (byte) 0x83,
      (byte) 0x04,
      (byte) 0xa7,
      (byte) 0xcb,
      (byte) 0x10,
      (byte) 0x18,
      (byte) 0x20,
      (byte) 0xcb,
      (byte) 0x1a,
      (byte) 0x61,
      (byte) 0xe3,
      (byte) 0x1f,
      (byte) 0x40,
      (byte) 0xfd,
      (byte) 0x77,
      (byte) 0xd4,
      (byte) 0xfe,
      (byte) 0x1b,
      (byte) 0x4f,
      (byte) 0x74,
      (byte) 0xa0,
      (byte) 0x5d,
      (byte) 0x1d,
      (byte) 0x2b,
      (byte) 0x6b,
      (byte) 0x85,
      (byte) 0x58,
      (byte) 0x67,
      (byte) 0x22,
      (byte) 0xa7,
      (byte) 0x10,
      (byte) 0xb4,
      (byte) 0x99,
      (byte) 0x87,
      (byte) 0x8d,
      (byte) 0x3f,
      (byte) 0xd9,
      (byte) 0xfb,
      (byte) 0xba,
      (byte) 0xe3,
      (byte) 0x45,
      (byte) 0x58
    }
  };
  private static final byte[][] ECDSAKEY_521 = {
    // pubX
    {
      (byte) 0x01,
      (byte) 0xf0,
      (byte) 0xb3,
      (byte) 0x4f,
      (byte) 0x92,
      (byte) 0x73,
      (byte) 0x0e,
      (byte) 0x18,
      (byte) 0x80,
      (byte) 0x56,
      (byte) 0x70,
      (byte) 0xa5,
      (byte) 0x4f,
      (byte) 0x74,
      (byte) 0x2e,
      (byte) 0xa0,
      (byte) 0x56,
      (byte) 0xf2,
      (byte) 0x67,
      (byte) 0x25,
      (byte) 0x93,
      (byte) 0x08,
      (byte) 0x19,
      (byte) 0x37,
      (byte) 0xed,
      (byte) 0x45,
      (byte) 0xa2,
      (byte) 0x53,
      (byte) 0x6e,
      (byte) 0x74,
      (byte) 0x50,
      (byte) 0x95,
      (byte) 0x46,
      (byte) 0x2a,
      (byte) 0x46,
      (byte) 0x75,
      (byte) 0x96,
      (byte) 0x76,
      (byte) 0x92,
      (byte) 0xc2,
      (byte) 0xe2,
      (byte) 0xfa,
      (byte) 0xce,
      (byte) 0xa4,
      (byte) 0x19,
      (byte) 0x81,
      (byte) 0x62,
      (byte) 0xee,
      (byte) 0x69,
      (byte) 0xb6,
      (byte) 0xa5,
      (byte) 0xf2,
      (byte) 0x81,
      (byte) 0x22,
      (byte) 0x6e,
      (byte) 0x8f,
      (byte) 0x12,
      (byte) 0x3d,
      (byte) 0x6b,
      (byte) 0x82,
      (byte) 0x17,
      (byte) 0xb3,
      (byte) 0x3f,
      (byte) 0xa5,
      (byte) 0xf0,
      (byte) 0xdc
    },
    // pubY
    {
      (byte) 0x01,
      (byte) 0xdd,
      (byte) 0x63,
      (byte) 0x19,
      (byte) 0x2c,
      (byte) 0x1d,
      (byte) 0xe4,
      (byte) 0xaa,
      (byte) 0xc3,
      (byte) 0x39,
      (byte) 0x74,
      (byte) 0xd9,
      (byte) 0xf3,
      (byte) 0x69,
      (byte) 0x29,
      (byte) 0x20,
      (byte) 0x07,
      (byte) 0x0f,
      (byte) 0x1e,
      (byte) 0x82,
      (byte) 0xbc,
      (byte) 0xc5,
      (byte) 0x46,
      (byte) 0xa9,
      (byte) 0x5b,
      (byte) 0x83,
      (byte) 0x8e,
      (byte) 0xd3,
      (byte) 0x5b,
      (byte) 0x3e,
      (byte) 0xa2,
      (byte) 0x3b,
      (byte) 0x63,
      (byte) 0x86,
      (byte) 0xf9,
      (byte) 0xe4,
      (byte) 0x4a,
      (byte) 0x47,
      (byte) 0xb7,
      (byte) 0xf8,
      (byte) 0x30,
      (byte) 0x70,
      (byte) 0xb0,
      (byte) 0xee,
      (byte) 0xda,
      (byte) 0xd0,
      (byte) 0x43,
      (byte) 0x22,
      (byte) 0xb3,
      (byte) 0xec,
      (byte) 0xa8,
      (byte) 0xf9,
      (byte) 0xe9,
      (byte) 0x1b,
      (byte) 0x52,
      (byte) 0xa2,
      (byte) 0xcb,
      (byte) 0xe0,
      (byte) 0x05,
      (byte) 0x08,
      (byte) 0x3b,
      (byte) 0x20,
      (byte) 0x27,
      (byte) 0x80,
      (byte) 0xe9,
      (byte) 0x6d
    },
    // Priv
    {
      (byte) 0x00,
      (byte) 0xe9,
      (byte) 0x3a,
      (byte) 0xba,
      (byte) 0xf5,
      (byte) 0x66,
      (byte) 0x69,
      (byte) 0x34,
      (byte) 0x6d,
      (byte) 0x37,
      (byte) 0x9a,
      (byte) 0xdd,
      (byte) 0xf1,
      (byte) 0x91,
      (byte) 0xf0,
      (byte) 0x40,
      (byte) 0x9e,
      (byte) 0x89,
      (byte) 0x08,
      (byte) 0x5e,
      (byte) 0xc9,
      (byte) 0x16,
      (byte) 0xb6,
      (byte) 0x03,
      (byte) 0x08,
      (byte) 0xb9,
      (byte) 0x00,
      (byte) 0x48,
      (byte) 0x62,
      (byte) 0xa8,
      (byte) 0xe4,
      (byte) 0xe8,
      (byte) 0x97,
      (byte) 0x28,
      (byte) 0x17,
      (byte) 0x31,
      (byte) 0x9d,
      (byte) 0xa2,
      (byte) 0xcb,
      (byte) 0xc1,
      (byte) 0x7f,
      (byte) 0xfb,
      (byte) 0x19,
      (byte) 0x24,
      (byte) 0xfd,
      (byte) 0x75,
      (byte) 0x7b,
      (byte) 0x91,
      (byte) 0xbd,
      (byte) 0xa1,
      (byte) 0x5b,
      (byte) 0x9a,
      (byte) 0x2a,
      (byte) 0x93,
      (byte) 0xeb,
      (byte) 0x82,
      (byte) 0x4d,
      (byte) 0x0f,
      (byte) 0xe6,
      (byte) 0x2f,
      (byte) 0x4b,
      (byte) 0xeb,
      (byte) 0xfc,
      (byte) 0x4a,
      (byte) 0xa9,
      (byte) 0x6c
    }
  };

  /** Pss Parameters */
  public static class PssParams {
    public PssParams(
        Enums.HashType sigHash, Enums.HashType mgf1Hash, int bitLength, int saltLength) {
      this.sigHash = sigHash;
      this.mgf1Hash = mgf1Hash;
      this.bitLength = bitLength;
      this.saltLength = saltLength;
    }

    public Enums.HashType sigHash;
    public Enums.HashType mgf1Hash;
    public int bitLength;
    public int saltLength;
  }

  @DataPoints("pss_valid")
  public static final PssParams[] PARAMS_PSS_VALID =
      new PssParams[] {
        new PssParams(Enums.HashType.SHA256, Enums.HashType.SHA256, 2048, 32),
        new PssParams(Enums.HashType.SHA256, Enums.HashType.SHA256, 3072, 32),
        new PssParams(Enums.HashType.SHA256, Enums.HashType.SHA256, 4096, 32),
        new PssParams(Enums.HashType.SHA384, Enums.HashType.SHA384, 2048, 48),
        new PssParams(Enums.HashType.SHA384, Enums.HashType.SHA384, 3072, 48),
        new PssParams(Enums.HashType.SHA384, Enums.HashType.SHA384, 4096, 48),
        new PssParams(Enums.HashType.SHA512, Enums.HashType.SHA512, 2048, 64),
        new PssParams(Enums.HashType.SHA512, Enums.HashType.SHA512, 3072, 64),
        new PssParams(Enums.HashType.SHA512, Enums.HashType.SHA512, 4096, 64),
        // Different hash functions are not supported by Tink, but the test currently happens in
        // SigUtil.validateRsaSsaPssParams which is called by the key manager, not in the self test
        // validation.
        new PssParams(Enums.HashType.SHA256, Enums.HashType.SHA512, 2048, 32),
      };

  @DataPoints("pss_invalid")
  public static final PssParams[] PARAMS_PSS_INVALID =
      new PssParams[] {
        // Low security: SHA1
        new PssParams(Enums.HashType.SHA1, Enums.HashType.SHA1, 2048, 20),
        // Low security: 1024 bit keys
        new PssParams(Enums.HashType.SHA256, Enums.HashType.SHA256, 1024, 20),
        // Unsupported modulus sizes.
        new PssParams(Enums.HashType.SHA256, Enums.HashType.SHA256, 2047, 32),
        new PssParams(Enums.HashType.SHA256, Enums.HashType.SHA256, 2047, 32),
        new PssParams(Enums.HashType.SHA384, Enums.HashType.SHA384, 2047, 48),
        new PssParams(Enums.HashType.SHA512, Enums.HashType.SHA512, 2047, 64),
      };

  /** Pkcs Parameters */
  public static class PkcsParams {
    public PkcsParams(Enums.HashType hash, int bitLength) {
      this.hash = hash;
      this.bitLength = bitLength;
    }

    public Enums.HashType hash;
    public int bitLength;
  }

  @DataPoints("pkcs_valid")
  public static PkcsParams[] parametersPkcs1Valid() {
    return new PkcsParams []{
      new PkcsParams(Enums.HashType.SHA256, 2048),
      new PkcsParams(Enums.HashType.SHA256, 3072),
      new PkcsParams(Enums.HashType.SHA256, 4096),
      new PkcsParams(Enums.HashType.SHA384, 2048),
      new PkcsParams(Enums.HashType.SHA384, 3072),
      new PkcsParams(Enums.HashType.SHA384, 4096),
      new PkcsParams(Enums.HashType.SHA512, 2048),
      new PkcsParams(Enums.HashType.SHA512, 3072),
      new PkcsParams(Enums.HashType.SHA512, 4096),
    };
  }

  @DataPoints("pkcs_invalid")
  public static Object[] parametersPkcs1Invalid() {
    return new Object[] {
      // Low security
      new PkcsParams(Enums.HashType.SHA1, 2048),
      new PkcsParams(Enums.HashType.SHA256, 1024),
      // Odd modulus sizes
      new PkcsParams(Enums.HashType.SHA256, 2047),
      new PkcsParams(Enums.HashType.SHA384, 2047),
      new PkcsParams(Enums.HashType.SHA512, 2047),
    };
  }

  public static final String[] getRsaKeyInfo(int keySize) throws Exception {
    switch (keySize) {
      case 2048:
        return RSAKEY_2048;
      case 3072:
        return RSAKEY_3072;
      case 4096:
      default:
        return RSAKEY_4096;
    }
  }

  private final void createRsaKey(int bitLength) throws Exception {
    String[] keyInfo = getRsaKeyInfo(bitLength);
    KeyFactory kf = EngineFactory.KEY_FACTORY.getInstance("RSA");
    publicRsaKey =
        (RSAPublicKey)
            kf.generatePublic(
                new RSAPublicKeySpec(
                    new BigInteger(keyInfo[0].substring(keyInfo[0].length() - (bitLength / 4)), 16),
                    BigInteger.valueOf(65537)));

    privateRsaKey =
        (RSAPrivateCrtKey)
            kf.generatePrivate(
                new RSAPrivateCrtKeySpec(
                    new BigInteger(keyInfo[0], 16),
                    BigInteger.valueOf(65537),
                    new BigInteger(keyInfo[1], 16),
                    new BigInteger(keyInfo[2], 16),
                    new BigInteger(keyInfo[3], 16),
                    new BigInteger(keyInfo[4], 16),
                    new BigInteger(keyInfo[5], 16),
                    new BigInteger(keyInfo[6], 16)));
  }

  // Note: we use Theory as a parametrized test -- different from what the Theory framework intends.
  @Theory
  public void testValidateRsaSsaPssValid(@FromDataPoints("pss_valid") PssParams params)
      throws Exception {
    createRsaKey(params.bitLength);
    SelfKeyTestValidators.validateRsaSsaPss(
        privateRsaKey, publicRsaKey, params.sigHash, params.mgf1Hash, params.saltLength);
  }

  // Note: we use Theory as a parametrized test -- different from what the Theory framework intends.
  @Theory
  public void testValidateRsaSsaPssInvalid(@FromDataPoints("pss_invalid") PssParams params)
      throws Exception {
    createRsaKey(params.bitLength);
    assertThrows(
        Exception.class,
        () ->
            SelfKeyTestValidators.validateRsaSsaPss(
                privateRsaKey, publicRsaKey, params.sigHash, params.mgf1Hash, params.saltLength));
  }

  // Note: we use Theory as a parametrized test -- different from what the Theory framework intends.
  @Theory
  public void testValidateRsaSsaPkcs1Valid(@FromDataPoints("pkcs_valid") PkcsParams params)
      throws Exception {
    createRsaKey(params.bitLength);
    SelfKeyTestValidators.validateRsaSsaPkcs1(privateRsaKey, publicRsaKey, params.hash);
  }

  // Note: we use Theory as a parametrized test -- different from what the Theory framework intends.
  @Theory
  public void testValidateRsaSsaPkcs1Invalid(@FromDataPoints("pkcs_invalid") PkcsParams params)
      throws Exception {
    createRsaKey(params.bitLength);
    assertThrows(
        Exception.class,
        () -> SelfKeyTestValidators.validateRsaSsaPkcs1(privateRsaKey, publicRsaKey, params.hash));
  }

  /** Ecdsa parameters */
  public static class EcdsaParams {
    public EcdsaParams(Enums.HashType hash, EllipticCurves.CurveType curveType) {
      this.hash = hash;
      this.curveType = curveType;
    }

    public Enums.HashType hash;
    public EllipticCurves.CurveType curveType;
  }

  @DataPoints("ecdsa_valid")
  public static EcdsaParams[] parametersEcdsaValid =
      new EcdsaParams[] {
        new EcdsaParams(Enums.HashType.SHA256, EllipticCurves.CurveType.NIST_P256),
        new EcdsaParams(Enums.HashType.SHA384, EllipticCurves.CurveType.NIST_P384),
        new EcdsaParams(Enums.HashType.SHA512, EllipticCurves.CurveType.NIST_P521)
      };

  public static final byte[][] getEcdsaKeyInfo(EllipticCurves.CurveType curveType)
      throws Exception {
    switch (curveType) {
      case NIST_P256:
        return ECDSAKEY_256;
      case NIST_P384:
        return ECDSAKEY_384;
      case NIST_P521:
        return ECDSAKEY_521;
    }

    throw new Exception("invalid curve. Should never happen.");
  }

  private final void createEcdsaKey(EllipticCurves.CurveType curveType) throws Exception {
    byte[][] key = getEcdsaKeyInfo(curveType);
    publicEcdsaKey = EllipticCurves.getEcPublicKey(curveType, key[0], key[1]);

    privateEcdsaKey = EllipticCurves.getEcPrivateKey(curveType, key[2]);
  }

  // Note: we use Theory as a parametrized test -- different from what the Theory framework intends.
  @Theory
  public void testValidateEcdsaValid(@FromDataPoints("ecdsa_valid") EcdsaParams params)
      throws Exception {
    createEcdsaKey(params.curveType);
    SelfKeyTestValidators.validateEcdsa(
        privateEcdsaKey, publicEcdsaKey, params.hash, EllipticCurves.EcdsaEncoding.IEEE_P1363);
  }
}
