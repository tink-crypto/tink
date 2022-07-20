/**
 * @license
 * Copyright 2020 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import {fromRawKey as aesGcmFromRawKey} from './aes_gcm';
import * as Bytes from './bytes';
import * as Random from './random';

/** Asserts that an exception is the result of a Web Crypto error. */
function assertCryptoError(exception: unknown) {
  const message = String(exception);
  expect(message.startsWith('SecurityException: OperationError')).toBe(true);
}

describe('aes gcm test', function() {
  beforeEach(function() {
    // Use a generous promise timeout for running continuously.
    jasmine.DEFAULT_TIMEOUT_INTERVAL = 1000 * 1000;  // 1000s
  });

  afterEach(function() {
    // Reset the timeout.
    jasmine.DEFAULT_TIMEOUT_INTERVAL = 1000;  // 1s
  });

  it('basic', async function() {
    const aead = await aesGcmFromRawKey(Random.randBytes(16));
    for (let i = 0; i < 100; i++) {
      const msg = Random.randBytes(i);
      let ciphertext = await aead.encrypt(msg);
      let plaintext = await aead.decrypt(ciphertext);
      expect(ciphertext.length).toBe(12 /* iv */ + msg.length + 16 /* tag */);
      expect(Bytes.toHex(plaintext)).toBe(Bytes.toHex(msg));

      let aad = null;
      ciphertext = await aead.encrypt(msg, aad);
      plaintext = await aead.decrypt(ciphertext, aad);
      expect(ciphertext.length).toBe(12 /* iv */ + msg.length + 16 /* tag */);
      expect(Bytes.toHex(plaintext)).toBe(Bytes.toHex(msg));

      aad = Random.randBytes(20);
      ciphertext = await aead.encrypt(msg, aad);
      plaintext = await aead.decrypt(ciphertext, aad);
      expect(ciphertext.length).toBe(12 /* iv */ + msg.length + 16 /* tag */);
      expect(Bytes.toHex(plaintext)).toBe(Bytes.toHex(msg));
    }
  });

  it('probabilistic encryption', async function() {
    const aead = await aesGcmFromRawKey(Random.randBytes(16));
    const msg = Random.randBytes(20);
    const aad = Random.randBytes(20);
    const results = new Set();
    for (let i = 0; i < 100; i++) {
      const ciphertext = await aead.encrypt(msg, aad);
      results.add(Bytes.toHex(ciphertext));
    }
    expect(results.size).toBe(100);
  });

  it('bit flip ciphertext', async function() {
    const aead = await aesGcmFromRawKey(Random.randBytes(16));
    const plaintext = Random.randBytes(8);
    const aad = Random.randBytes(8);
    const ciphertext = await aead.encrypt(plaintext, aad);
    for (let i = 0; i < ciphertext.length; i++) {
      for (let j = 0; j < 8; j++) {
        const c1 = new Uint8Array(ciphertext);
        c1[i] = (c1[i] ^ (1 << j));
        try {
          await aead.decrypt(c1, aad);
          fail('expected aead.decrypt to fail');
        } catch (e) {
          assertCryptoError(e);
        }
      }
    }
  });

  it('bit flip aad', async function() {
    const aead = await aesGcmFromRawKey(Random.randBytes(16));
    const plaintext = Random.randBytes(8);
    const aad = Random.randBytes(8);
    const ciphertext = await aead.encrypt(plaintext, aad);
    for (let i = 0; i < aad.length; i++) {
      for (let j = 0; j < 8; j++) {
        const aad1 = new Uint8Array(aad);
        aad1[i] = (aad1[i] ^ (1 << j));
        try {
          await aead.decrypt(ciphertext, aad1);
          fail('expected aead.decrypt to fail');
        } catch (e) {
          assertCryptoError(e);
        }
      }
    }
  });

  it('truncation', async function() {
    const aead = await aesGcmFromRawKey(Random.randBytes(16));
    const plaintext = Random.randBytes(8);
    const aad = Random.randBytes(8);
    const ciphertext = await aead.encrypt(plaintext, aad);
    for (let i = 1; i <= ciphertext.length; i++) {
      const c1 = new Uint8Array(ciphertext.buffer, 0, ciphertext.length - i);
      try {
        await aead.decrypt(c1, aad);
        fail('expected aead.decrypt to fail');
        // Preserving old behavior when moving to
        // https://www.typescriptlang.org/tsconfig#useUnknownInCatchVariables
        // tslint:disable-next-line:no-any
      } catch (e: any) {
        if (c1.length < 12 /* iv */ + 16 /* tag */) {
          expect(e.toString()).toBe('SecurityException: ciphertext too short');
        } else {
          assertCryptoError(e);
        }
      }
    }
  });

  it('with nist test vectors', async function() {
    // Download from
    // https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/CAVP-TESTING-BLOCK-CIPHER-MODES.
    const NIST_TEST_VECTORS =
        [
          {
            'Key':
                'b52c505a37d78eda5dd34f20c22540ea1b58963cf8e5bf8ffa85f9f2492505b4',
            'IV': '516c33929df5a3284ff463d7',
            'PT': '',
            'AAD': '',
            'CT': '',
            'Tag': 'bdc1ac884d332457a1d2664f168c76f0',
          },
          {
            'Key':
                '78dc4e0aaf52d935c3c01eea57428f00ca1fd475f5da86a49c8dd73d68c8e223',
            'IV': 'd79cf22d504cc793c3fb6c8a',
            'PT': '',
            'AAD': 'b96baa8c1c75a671bfb2d08d06be5f36',
            'CT': '',
            'Tag': '3e5d486aa2e30b22e040b85723a06e76',
          },
          {
            'Key':
                '886cff5f3e6b8d0e1ad0a38fcdb26de97e8acbe79f6bed66959a598fa5047d65',
            'IV': '3a8efa1cd74bbab5448f9945',
            'PT': '',
            'AAD': '519fee519d25c7a304d6c6aa1897ee1eb8c59655',
            'CT': '',
            'Tag': 'f6d47505ec96c98a42dc3ae719877b87',
          },
          {
            'Key':
                'f4069bb739d07d0cafdcbc609ca01597f985c43db63bbaaa0debbb04d384e49c',
            'IV': 'd25ff30fdc3d464fe173e805',
            'PT': '',
            'AAD':
                '3e1449c4837f0892f9d55127c75c4b25d69be334baf5f19394d2d8bb460cbf2120e14736d0f634aa792feca20e455f11',
            'CT': '',
            'Tag': '805ec2931c2181e5bfb74fa0a975f0cf',
          },
          {
            'Key':
                '03ccb7dbc7b8425465c2c3fc39ed0593929ffd02a45ff583bd89b79c6f646fe9',
            'IV': 'fd119985533bd5520b301d12',
            'PT': '',
            'AAD':
                '98e68c10bf4b5ae62d434928fc6405147c6301417303ef3a703dcfd2c0c339a4d0a89bd29fe61fecf1066ab06d7a5c31a48ffbfed22f749b17e9bd0dc1c6f8fbd6fd4587184db964d5456132106d782338c3f117ec05229b0899',
            'CT': '',
            'Tag': 'cf54e7141349b66f248154427810c87a',
          },
          {
            'Key':
                '31bdadd96698c204aa9ce1448ea94ae1fb4a9a0b3c9d773b51bb1822666b8f22',
            'IV': '0d18e06c7c725ac9e362e1ce',
            'PT': '2db5168e932556f8089a0622981d017d',
            'AAD': '',
            'CT': 'fa4362189661d163fcd6a56d8bf0405a',
            'Tag': 'd636ac1bbedd5cc3ee727dc2ab4a9489',
          },
          {
            'Key':
                '92e11dcdaa866f5ce790fd24501f92509aacf4cb8b1339d50c9c1240935dd08b',
            'IV': 'ac93a1a6145299bde902f21a',
            'PT': '2d71bcfa914e4ac045b2aa60955fad24',
            'AAD': '1e0889016f67601c8ebea4943bc23ad6',
            'CT': '8995ae2e6df3dbf96fac7b7137bae67f',
            'Tag': 'eca5aa77d51d4a0a14d9c51e1da474ab',
          },
          {
            'Key':
                '83688deb4af8007f9b713b47cfa6c73e35ea7a3aa4ecdb414dded03bf7a0fd3a',
            'IV': '0b459724904e010a46901cf3',
            'PT': '33d893a2114ce06fc15d55e454cf90c3',
            'AAD': '794a14ccd178c8ebfd1379dc704c5e208f9d8424',
            'CT': 'cc66bee423e3fcd4c0865715e9586696',
            'Tag': '0fb291bd3dba94a1dfd8b286cfb97ac5',
          },
          {
            'Key':
                'e4fed339c7b0cd267305d11ab0d5c3273632e8872d35bdc367a1363438239a35',
            'IV': '0365882cf75432cfd23cbd42',
            'PT': 'fff39a087de39a03919fbd2f2fa5f513',
            'AAD':
                '8a97d2af5d41160ac2ff7dd8ba098e7aa4d618f0f455957d6a6d0801796747ba57c32dfbaaaf15176528fe3a0e4550c9',
            'CT': '8d9e68f03f7e5f4a0ffaa7650d026d08',
            'Tag': '3554542c478c0635285a61d1b51f6afa',
          },
          {
            'Key':
                '80d755e24d129e68a5259ec2cf618e39317074a83c8961d3768ceb2ed8d5c3d7',
            'IV': '7598c07ba7b16cd12cf50813',
            'PT': '5e7fd1298c4f15aa0f1c1e47217aa7a9',
            'AAD':
                '0e94f4c48fd0c9690c853ad2a5e197c5de262137b69ed0cdfa28d8d12413e4ffff15374e1cccb0423e8ed829a954a335ed705a272ad7f9abd1057c849bb0d54b768e9d79879ec552461cc04adb6ca0040c5dd5bc733d21a93702',
            'CT': '5762a38cf3f2fdf3645d2f6696a7eead',
            'Tag': '8a6708e69468915c5367573924fe1ae3',
          },
          {
            'Key':
                '82c4f12eeec3b2d3d157b0f992d292b237478d2cecc1d5f161389b97f999057a',
            'IV': '7b40b20f5f397177990ef2d1',
            'PT': '982a296ee1cd7086afad976945',
            'AAD': '',
            'CT': 'ec8e05a0471d6b43a59ca5335f',
            'Tag': '113ddeafc62373cac2f5951bb9165249',
          },
          {
            'Key':
                'dad89d9be9bba138cdcf8752c45b579d7e27c3dbb40f53e771dd8cfd500aa2d5',
            'IV': 'cfb2aec82cfa6c7d89ee72ff',
            'PT': 'b526ba1050177d05b0f72f8d67',
            'AAD': '6e43784a91851a77667a02198e28dc32',
            'CT': '8b29e66e924ecae84f6d8f7d68',
            'Tag': '1e365805c8f28b2ed8a5cadfd9079158',
          },
          {
            'Key':
                '69b458f2644af9020463b40ee503cdf083d693815e2659051ae0d039e606a970',
            'IV': '8d1da8ab5f91ccd09205944b',
            'PT': 'f3e0e09224256bf21a83a5de8d',
            'AAD': '036ad5e5494ef817a8af2f5828784a4bfedd1653',
            'CT': 'c0a62d77e6031bfdc6b13ae217',
            'Tag': 'a794a9aaee48cd92e47761bf1baff0af',
          },
          {
            'Key':
                '5f671466378f470ba5f5160e2209f3d95a48b7e560625d5a08654414de23aee2',
            'IV': '6b3c08a663d04132243dd96c',
            'PT': 'c428592d9f8a7f107ec4d0df05',
            'AAD':
                '12965559c31d538f937bda6eee9c93b0387318dc5d9496fb1c3a0b9b978dbfebff2a5823974ee9d679834dbe59f7ec51',
            'CT': '1d8d7fe4357080c817303ce19c',
            'Tag': 'e88d6b566fdc7b4fd62106bd2eb806ec',
          },
          {
            'Key':
                'ff9506b4d46ba54128876fadfcc673a4c927c618ea7d95cfcaa508cbc8f7fc66',
            'IV': '3742ad2208a0484345eee1be',
            'PT': '7fd0d6cadc92cad27bb2d7d8c8',
            'AAD':
                'f1360a27fdc244be8739d85af6491c762a693aafe668c449515fdeeedb6a90aeee3891bbc8b69adc6a6426cb12fcdebc32c9f58c5259d128b91efa28620a3a9a0168b0ff5e76951cb41647ba4aa1f87fac0d97ac580e42cffc7e',
            'CT': 'bdb8346b28eb4d7226493611a6',
            'Tag': '7484d827b767647f44c7f94a39f8175c',
          },
          {
            'Key':
                '268ed1b5d7c9c7304f9cae5fc437b4cd3aebe2ec65f0d85c3918d3d3b5bba89b',
            'IV': '9ed9d8180564e0e945f5e5d4',
            'PT':
                'fe29a40d8ebf57262bdb87191d01843f4ca4b2de97d88273154a0b7d9e2fdb80',
            'AAD': '',
            'CT':
                '791a4a026f16f3a5ea06274bf02baab469860abde5e645f3dd473a5acddeecfc',
            'Tag': '05b2b74db0662550435ef1900e136b15',
          },
          {
            'Key':
                '37ccdba1d929d6436c16bba5b5ff34deec88ed7df3d15d0f4ddf80c0c731ee1f',
            'IV': '5c1b21c8998ed6299006d3f9',
            'PT':
                'ad4260e3cdc76bcc10c7b2c06b80b3be948258e5ef20c508a81f51e96a518388',
            'AAD': '22ed235946235a85a45bc5fad7140bfa',
            'CT':
                '3b335f8b08d33ccdcad228a74700f1007542a4d1e7fc1ebe3f447fe71af29816',
            'Tag': '1fbf49cc46f458bf6e88f6370975e6d4',
          },
          {
            'Key':
                '5853c020946b35f2c58ec427152b840420c40029636adcbb027471378cfdde0f',
            'IV': 'eec313dd07cc1b3e6b068a47',
            'PT':
                'ce7458e56aef9061cb0c42ec2315565e6168f5a6249ffd31610b6d17ab64935e',
            'AAD': '1389b522c24a774181700553f0246bbabdd38d6f',
            'CT':
                'eadc3b8766a77ded1a58cb727eca2a9790496c298654cda78febf0da16b6903b',
            'Tag': '3d49a5b32fde7eafcce90079217ffb57',
          },
          {
            'Key':
                'dc776f0156c15d032623854b625c61868e5db84b7b6f9fbd3672f12f0025e0f6',
            'IV': '67130951c4a57f6ae7f13241',
            'PT':
                '9378a727a5119595ad631b12a5a6bc8a91756ef09c8d6eaa2b718fe86876da20',
            'AAD':
                'fd0920faeb7b212932280a009bac969145e5c316cf3922622c3705c3457c4e9f124b2076994323fbcfb523f8ed16d241',
            'CT':
                '6d958c20870d401a3c1f7a0ac092c97774d451c09f7aae992a8841ff0ab9d60d',
            'Tag': 'b876831b4ecd7242963b040aa45c4114',
          },
          {
            'Key':
                '26bf255bee60ef0f653769e7034db95b8c791752754e575c761059e9ee8dcf78',
            'IV': 'cecd97ab07ce57c1612744f5',
            'PT':
                '96983917a036650763aca2b4e927d95ffc74339519ed40c4336dba91edfbf9ad',
            'AAD':
                'afebbe9f260f8c118e52b84d8880a34622675faef334cdb41be9385b7d059b79c0f8a432d25f8b71e781b177fce4d4c57ac5734543e85d7513f96382ff4b2d4b95b2f1fdbaf9e78bbd1db13a7dd26e8a4ac83a3e8ab42d1d545f',
            'CT':
                'e34b1540a769f7913331d66796e00bdc3ee0f258cf244eb7663375cc5ad6c658',
            'Tag': '3841f02beb7a7fca7e578922d0a2f80c',
          },
          {
            'Key':
                '1fded32d5999de4a76e0f8082108823aef60417e1896cf4218a2fa90f632ec8a',
            'IV': '1f3afa4711e9474f32e70462',
            'PT':
                '06b2c75853df9aeb17befd33cea81c630b0fc53667ff45199c629c8e15dce41e530aa792f796b8138eeab2e86c7b7bee1d40b0',
            'AAD': '',
            'CT':
                '91fbd061ddc5a7fcc9513fcdfdc9c3a7c5d4d64cedf6a9c24ab8a77c36eefbf1c5dc00bc50121b96456c8cd8b6ff1f8b3e480f',
            'Tag': '30096d340f3d5c42d82a6f475def23eb',
          },
          {
            'Key':
                '5fe01c4baf01cbe07796d5aaef6ec1f45193a98a223594ae4f0ef4952e82e330',
            'IV': 'bd587321566c7f1a5dd8652d',
            'PT':
                '881dc6c7a5d4509f3c4bd2daab08f165ddc204489aa8134562a4eac3d0bcad7965847b102733bb63d1e5c598ece0c3e5dadddd',
            'AAD': '9013617817dda947e135ee6dd3653382',
            'CT':
                '16e375b4973b339d3f746c1c5a568bc7526e909ddff1e19c95c94a6ccff210c9a4a40679de5760c396ac0e2ceb1234f9f5fe26',
            'Tag': 'abd3d26d65a6275f7a4f56b422acab49',
          },
          {
            'Key':
                '24501ad384e473963d476edcfe08205237acfd49b5b8f33857f8114e863fec7f',
            'IV': '9ff18563b978ec281b3f2794',
            'PT':
                '27f348f9cdc0c5bd5e66b1ccb63ad920ff2219d14e8d631b3872265cf117ee86757accb158bd9abb3868fdc0d0b074b5f01b2c',
            'AAD': 'adb5ec720ccf9898500028bf34afccbcaca126ef',
            'CT':
                'eb7cb754c824e8d96f7c6d9b76c7d26fb874ffbf1d65c6f64a698d839b0b06145dae82057ad55994cf59ad7f67c0fa5e85fab8',
            'Tag': 'bc95c532fecc594c36d1550286a7a3f0',
          },
          {
            'Key':
                '463b412911767d57a0b33969e674ffe7845d313b88c6fe312f3d724be68e1fca',
            'IV': '611ce6f9a6880750de7da6cb',
            'PT':
                'e7d1dcf668e2876861940e012fe52a98dacbd78ab63c08842cc9801ea581682ad54af0c34d0d7f6f59e8ee0bf4900e0fd85042',
            'AAD':
                '0a682fbc6192e1b47a5e0868787ffdafe5a50cead3575849990cdd2ea9b3597749403efb4a56684f0c6bde352d4aeec5',
            'CT':
                '8886e196010cb3849d9c1a182abe1eeab0a5f3ca423c3669a4a8703c0f146e8e956fb122e0d721b869d2b6fcd4216d7d4d3758',
            'Tag': '2469cecd70fd98fec9264f71df1aee9a',
          },
          {
            'Key':
                '148579a3cbca86d5520d66c0ec71ca5f7e41ba78e56dc6eebd566fed547fe691',
            'IV': 'b08a5ea1927499c6ecbfd4e0',
            'PT':
                '9d0b15fdf1bd595f91f8b3abc0f7dec927dfd4799935a1795d9ce00c9b879434420fe42c275a7cd7b39d638fb81ca52b49dc41',
            'AAD':
                'e4f963f015ffbb99ee3349bbaf7e8e8e6c2a71c230a48f9d59860a29091d2747e01a5ca572347e247d25f56ba7ae8e05cde2be3c97931292c02370208ecd097ef692687fecf2f419d3200162a6480a57dad408a0dfeb492e2c5d',
            'CT':
                '2097e372950a5e9383c675e89eea1c314f999159f5611344b298cda45e62843716f215f82ee663919c64002a5c198d7878fd3f',
            'Tag': 'adbecdb0d5c2224d804d2886ff9a5760',
          },
          {
            'Key': '11754cd72aec309bf52f7687212e8957',
            'IV': '3c819d9a9bed087615030b65',
            'PT': '',
            'AAD': '',
            'CT': '',
            'Tag': '250327c674aaf477aef2675748cf6971',
          },
          {
            'Key': '77be63708971c4e240d1cb79e8d77feb',
            'IV': 'e0e00f19fed7ba0136a797f3',
            'PT': '',
            'AAD': '7a43ec1d9c0a5a78a0b16533a6213cab',
            'CT': '',
            'Tag': '209fcc8d3675ed938e9c7166709dd946',
          },
          {
            'Key': '2fb45e5b8f993a2bfebc4b15b533e0b4',
            'IV': '5b05755f984d2b90f94b8027',
            'PT': '',
            'AAD': 'e85491b2202caf1d7dce03b97e09331c32473941',
            'CT': '',
            'Tag': 'c75b7832b2a2d9bd827412b6ef5769db',
          },
          {
            'Key': '99e3e8793e686e571d8285c564f75e2b',
            'IV': 'c2dd0ab868da6aa8ad9c0d23',
            'PT': '',
            'AAD':
                'b668e42d4e444ca8b23cfdd95a9fedd5178aa521144890b093733cf5cf22526c5917ee476541809ac6867a8c399309fc',
            'CT': '',
            'Tag': '3f4fba100eaf1f34b0baadaae9995d85',
          },
          {
            'Key': '20b5b6b854e187b058a84d57bc1538b6',
            'IV': '94c1935afc061cbf254b936f',
            'PT': '',
            'AAD':
                'ca418e71dbf810038174eaa3719b3fcb80531c7110ad9192d105eeaafa15b819ac005668752b344ed1b22faf77048baf03dbddb3b47d6b00e95c4f005e0cc9b7627ccafd3f21b3312aa8d91d3fa0893fe5bff7d44ca46f23afe0',
            'CT': '',
            'Tag': 'b37286ebaf4a54e0ffc2a1deafc9f6db',
          },
          {
            'Key': '7fddb57453c241d03efbed3ac44e371c',
            'IV': 'ee283a3fc75575e33efd4887',
            'PT': 'd5de42b461646c255c87bd2962d3b9a2',
            'AAD': '',
            'CT': '2ccda4a5415cb91e135c2a0f78c9b2fd',
            'Tag': 'b36d1df9b9d5e596f83e8b7f52971cb3',
          },
          {
            'Key': 'c939cc13397c1d37de6ae0e1cb7c423c',
            'IV': 'b3d8cc017cbb89b39e0f67e2',
            'PT': 'c3b3c41f113a31b73d9a5cd432103069',
            'AAD': '24825602bd12a984e0092d3e448eda5f',
            'CT': '93fe7d9e9bfd10348a5606e5cafa7354',
            'Tag': '0032a1dc85f1c9786925a2e71d8272dd',
          },
          {
            'Key': 'd4a22488f8dd1d5c6c19a7d6ca17964c',
            'IV': 'f3d5837f22ac1a0425e0d1d5',
            'PT': '7b43016a16896497fb457be6d2a54122',
            'AAD': 'f1c5d424b83f96c6ad8cb28ca0d20e475e023b5a',
            'CT': 'c2bd67eef5e95cac27e3b06e3031d0a8',
            'Tag': 'f23eacf9d1cdf8737726c58648826e9c',
          },
          {
            'Key': '89850dd398e1f1e28443a33d40162664',
            'IV': 'e462c58482fe8264aeeb7231',
            'PT': '2805cdefb3ef6cc35cd1f169f98da81a',
            'AAD':
                'd74e99d1bdaa712864eec422ac507bddbe2b0d4633cd3dff29ce5059b49fe868526c59a2a3a604457bc2afea866e7606',
            'CT': 'ba80e244b7fc9025cd031d0f63677e06',
            'Tag': 'd84a8c3eac57d1bb0e890a8f461d1065',
          },
          {
            'Key': 'bd7c5c63b7542b56a00ebe71336a1588',
            'IV': '87721f23ba9c3c8ea5571abc',
            'PT': 'de15ddbb1e202161e8a79af6a55ac6f3',
            'AAD':
                'a6ec8075a0d3370eb7598918f3b93e48444751624997b899a87fa6a9939f844e008aa8b70e9f4c3b1a19d3286bf543e7127bfecba1ad17a5ec53fccc26faecacc4c75369498eaa7d706aef634d0009279b11e4ba6c993e5e9ed9',
            'CT': '41eb28c0fee4d762de972361c863bc80',
            'Tag': '9cb567220d0b252eb97bff46e4b00ff8',
          },
          {
            'Key': 'fe9bb47deb3a61e423c2231841cfd1fb',
            'IV': '4d328eb776f500a2f7fb47aa',
            'PT': 'f1cc3818e421876bb6b8bbd6c9',
            'AAD': '',
            'CT': 'b88c5c1977b35b517b0aeae967',
            'Tag': '43fd4727fe5cdb4b5b42818dea7ef8c9',
          },
          {
            'Key': 'dfefde23c6122bf0370ab5890e804b73',
            'IV': '92d6a8029990670f16de79e2',
            'PT': '64260a8c287de978e96c7521d0',
            'AAD': 'a2b16d78251de6c191ce350e5c5ef242',
            'CT': 'bf78de948a847c173649d4b4d0',
            'Tag': '9da3829968cdc50794d1c30d41cd4515',
          },
          {
            'Key': 'fe0121f42e599f88ff02a985403e19bb',
            'IV': '3bb9eb7724cbe1943d43de21',
            'PT': 'fd331ca8646091c29f21e5f0a1',
            'AAD': '2662d895035b6519f3510eae0faa3900ad23cfdf',
            'CT': '59fe29b07b0de8d869efbbd9b4',
            'Tag': 'd24c3e9c1c73c0af1097e26061c857de',
          },
          {
            'Key': 'cbd3b8dbfcfb11ce345706e6cd73881a',
            'IV': 'dc62bb68d0ec9a5d759d6741',
            'PT': '85f83bf598dfd55bc8bfde2a64',
            'AAD':
                '0944b661fe6294f3c92abb087ec1b259b032dc4e0c5f28681cbe6e63c2178f474326f35ad3ca80c28e3485e7e5b252c8',
            'CT': '206f6b3bb032dfecd39f8340b1',
            'Tag': '425a21b2ea90580c889134032b914bb5',
          },
          {
            'Key': 'e5b1e7a94e9e1fda0873571eec713429',
            'IV': '5ddde829a81713346af8e5b7',
            'PT': '850069e5ed768b5dc9ed7ad485',
            'AAD':
                'b0ce75da427fba93da6d3455b2b440a877599a6d8d6d2d66ee90b5cf9a33baaa8329a9ffaac290e8e33f2af2548c2a8a181b3d4d9f8fac860cc26b0d26b9cc53bc9f405afa73605ebeb376f2d1d7fcb065bab92f20f295556ade',
            'CT': 'c211d9079d5562659db01e17d1',
            'Tag': '884893fb035d3d7237d47c363de62bb3',
          },
          {
            'Key': '9971071059abc009e4f2bd69869db338',
            'IV': '07a9a95ea3821e9c13c63251',
            'PT':
                'f54bc3501fed4f6f6dfb5ea80106df0bd836e6826225b75c0222f6e859b35983',
            'AAD': '',
            'CT':
                '0556c159f84ef36cb1602b4526b12009c775611bffb64dc0d9ca9297cd2c6a01',
            'Tag': '7870d9117f54811a346970f1de090c41',
          },
          {
            'Key': '298efa1ccf29cf62ae6824bfc19557fc',
            'IV': '6f58a93fe1d207fae4ed2f6d',
            'PT':
                'cc38bccd6bc536ad919b1395f5d63801f99f8068d65ca5ac63872daf16b93901',
            'AAD': '021fafd238463973ffe80256e5b1c6b1',
            'CT':
                'dfce4e9cd291103d7fe4e63351d9e79d3dfd391e3267104658212da96521b7db',
            'Tag': '542465ef599316f73a7a560509a2d9f2',
          },
          {
            'Key': 'fedc7155192d00b23cdd98750db9ebba',
            'IV': 'a76b74f55c1a1756a08338b1',
            'PT':
                '6831435b8857daf1c513b148820d13b5a72cc490bda79a98a6f520d8763c39d1',
            'AAD': '2ad206c4176e7e552aa08836886816fafa77e759',
            'CT':
                '15823805da89a1923bfc1d6f87784d56bad1128b4dffdbdeefbb2fa562c35e68',
            'Tag': 'd23dc455ced49887c717e8eabeec2984',
          },
          {
            'Key': '48b7f337cdf9252687ecc760bd8ec184',
            'IV': '3e894ebb16ce82a53c3e05b2',
            'PT':
                'bb2bac67a4709430c39c2eb9acfabc0d456c80d30aa1734e57997d548a8f0603',
            'AAD':
                '7d924cfd37b3d046a96eb5e132042405c8731e06509787bbeb41f258275746495e884d69871f77634c584bb007312234',
            'CT':
                'd263228b8ce051f67e9baf1ce7df97d10cd5f3bc972362055130c7d13c3ab2e7',
            'Tag': '71446737ca1fa92e6d026d7d2ed1aa9c',
          },
          {
            'Key': '8fbf7ca12fd525dde91e625873fe51c2',
            'IV': '200bea517b9790a1cfadaf5e',
            'PT':
                '39d3e6277c4b4963840d1642e6faae0a5be2da97f61c4e55bb57ce021903d4c4',
            'AAD':
                'a414c07fe2e60bec9ccc409e9e899c6fe60580bb2607c861f7f08523e69cda1b9c3a711d1d9c35091771e4c950b9996d0ad04f2e00d1b3105853542a96e09ffffc2ec80f8cf88728f594f0aeb14f98a688234e8bfbf70327b364',
            'CT':
                'fe678ef76f69ac95db553b6dadd5a07a9dc8e151fe6a9fa3a1cd621636b87868',
            'Tag': '7c860774f88332b9a7ce6bbd0272a727',
          },
          {
            'Key': '594157ec4693202b030f33798b07176d',
            'IV': '49b12054082660803a1df3df',
            'PT':
                '3feef98a976a1bd634f364ac428bb59cd51fb159ec1789946918dbd50ea6c9d594a3a31a5269b0da6936c29d063a5fa2cc8a1c',
            'AAD': '',
            'CT':
                'c1b7a46a335f23d65b8db4008a49796906e225474f4fe7d39e55bf2efd97fd82d4167de082ae30fa01e465a601235d8d68bc69',
            'Tag': 'ba92d3661ce8b04687e8788d55417dc2',
          },
          {
            'Key': 'b61553bb854895b929751cd0c5f80384',
            'IV': '8863f999ae64e55d0bbd7457',
            'PT':
                '9b1b113217d0c4ea7943cf123c69c6ad2e3c97368c51c9754145d155dde1ee8640c8cafff17a5c9737d26a137eee4bf369096d',
            'AAD': 'd914b5f2d1b08ce53ea59cb310587245',
            'CT':
                'acfab4632b8a25805112f13d85e082bc89dc49bd92164fa8a2dad242c3a1b2f2696f2fdff579025f3f146ea97da3e47dc34b65',
            'Tag': '5d9b5f4a9868c1c69cbd6fd851f01340',
          },
          {
            'Key': 'fe47fcce5fc32665d2ae399e4eec72ba',
            'IV': '5adb9609dbaeb58cbd6e7275',
            'PT':
                '7c0e88c88899a779228465074797cd4c2e1498d259b54390b85e3eef1c02df60e743f1b840382c4bccaf3bafb4ca8429bea063',
            'AAD': '88319d6e1d3ffa5f987199166c8a9b56c2aeba5a',
            'CT':
                '98f4826f05a265e6dd2be82db241c0fbbbf9ffb1c173aa83964b7cf5393043736365253ddbc5db8778371495da76d269e5db3e',
            'Tag': '291ef1982e4defedaa2249f898556b47',
          },
          {
            'Key': '3c50622868f450aa0928990c15e1eb36',
            'IV': '811d5290768d57e7d87bb6c7',
            'PT':
                'edd0a8f82833e919740fe2bf9edecf4ac86c72dc89490cef7b6983aaaf99fc856c5cc87d63f98a7c861bf3271fea6da86a15ab',
            'AAD':
                'dae2c7e0a3d3fd2bc04eca19b15178a003b5cf84890c28c2a615f20f8adb427f70698c12b2ef87780c1193fbb8cd1674',
            'CT':
                'a51425b0608d3b4b46d4ec05ca1ddaf02bdd2089ae0554ecfb2a1c84c63d82dc71ddb9ab1b1f0b49de2ad27c2b5173e7000aa6',
            'Tag': 'bd9b5efca48008cd973a4f7d2c723844',
          },
          {
            'Key': '2c1f21cf0f6fb3661943155c3e3d8492',
            'IV': '23cb5ff362e22426984d1907',
            'PT':
                '42f758836986954db44bf37c6ef5e4ac0adaf38f27252a1b82d02ea949c8a1a2dbc0d68b5615ba7c1220ff6510e259f06655d8',
            'AAD':
                '5d3624879d35e46849953e45a32a624d6a6c536ed9857c613b572b0333e701557a713e3f010ecdf9a6bd6c9e3e44b065208645aff4aabee611b391528514170084ccf587177f4488f33cfb5e979e42b6e1cfc0a60238982a7aec',
            'CT':
                '81824f0e0d523db30d3da369fdc0d60894c7a0a20646dd015073ad2732bd989b14a222b6ad57af43e1895df9dca2a5344a62cc',
            'Tag': '57a3ee28136e94c74838997ae9823f3a',
          },
        ];
    for (let i = 0; i < NIST_TEST_VECTORS.length; i++) {
      const testVector = NIST_TEST_VECTORS[i];
      const aead = await aesGcmFromRawKey(Bytes.fromHex(testVector['Key']));
      const ciphertext = Bytes.fromHex(
          testVector['IV'] + testVector['CT'] + testVector['Tag']);
      const aad = Bytes.fromHex(testVector['AAD']);
      try {
        const plaintext = await aead.decrypt(ciphertext, aad);
        expect(testVector['PT']).toBe(Bytes.toHex(plaintext));
      } catch (e) {
        fail(e);
      }
    }
  });
});
