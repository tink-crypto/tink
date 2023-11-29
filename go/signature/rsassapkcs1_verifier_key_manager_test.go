// Copyright 2022 Google LLC
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

package signature_test

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"math/big"
	"testing"

	"google.golang.org/protobuf/proto"
	"github.com/google/tink/go/core/registry"
	internal "github.com/google/tink/go/internal/signature"
	"github.com/google/tink/go/subtle/random"
	"github.com/google/tink/go/tink"
	commonpb "github.com/google/tink/go/proto/common_go_proto"
	rsassapkcs1pb "github.com/google/tink/go/proto/rsa_ssa_pkcs1_go_proto"
)

const (
	rsaPKCS1PublicTypeURL = "type.googleapis.com/google.crypto.tink.RsaSsaPkcs1PublicKey"
)

func makeValidRSAPKCS1Key() (*rsassapkcs1pb.RsaSsaPkcs1PrivateKey, error) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		return nil, err
	}
	return &rsassapkcs1pb.RsaSsaPkcs1PrivateKey{
		Version: 0,
		PublicKey: &rsassapkcs1pb.RsaSsaPkcs1PublicKey{
			N:       rsaKey.PublicKey.N.Bytes(),
			E:       big.NewInt(int64(rsaKey.PublicKey.E)).Bytes(),
			Version: 0,
			Params: &rsassapkcs1pb.RsaSsaPkcs1Params{
				HashType: commonpb.HashType_SHA256,
			},
		},
		D:   rsaKey.D.Bytes(),
		P:   rsaKey.Primes[0].Bytes(),
		Q:   rsaKey.Primes[1].Bytes(),
		Dp:  rsaKey.Precomputed.Dp.Bytes(),
		Dq:  rsaKey.Precomputed.Dq.Bytes(),
		Crt: rsaKey.Precomputed.Qinv.Bytes(),
	}, nil
}

func TestRSASSAPKCS1VerifierDoesSupport(t *testing.T) {
	vkm, err := registry.GetKeyManager(rsaPKCS1PublicTypeURL)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", rsaPKCS1PublicTypeURL, err)
	}
	if !vkm.DoesSupport(rsaPKCS1PublicTypeURL) {
		t.Errorf("DoesSupport(%q) = false, want true", rsaPKCS1PublicTypeURL)
	}
	if vkm.DoesSupport("invalid.type.url") {
		t.Error("DoesSupport('invalid.type.url') = true, want false")
	}
}

func TestRSASSAPKCS1VerifierTypeURL(t *testing.T) {
	vkm, err := registry.GetKeyManager(rsaPKCS1PublicTypeURL)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", rsaPKCS1PublicTypeURL, err)
	}
	if vkm.TypeURL() != rsaPKCS1PublicTypeURL {
		t.Errorf("TypeURL() = %q, want %q", vkm.TypeURL(), rsaPKCS1PublicTypeURL)
	}
}

func TestRSASSAPKCS1VerifierNotImplemented(t *testing.T) {
	vkm, err := registry.GetKeyManager(rsaPKCS1PublicTypeURL)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", rsaPKCS1PublicTypeURL, err)
	}
	serializedFormat, err := proto.Marshal(&rsassapkcs1pb.RsaSsaPkcs1KeyFormat{
		Params: &rsassapkcs1pb.RsaSsaPkcs1Params{
			HashType: commonpb.HashType_SHA256,
		},
		ModulusSizeInBits: 3072,
		PublicExponent:    []byte{0x01, 0x00, 0x01},
	})
	if err != nil {
		t.Fatalf("proto.Marshall() err = %v, want nil", err)
	}
	if _, err := vkm.NewKeyData(serializedFormat); err == nil {
		t.Error("NewKeyData() err = nil, want error")
	}
	if _, err := vkm.NewKey(serializedFormat); err == nil {
		t.Error("NewKeyData() err = nil, want error")
	}
}

func TestRSASSAPKCS1VerifierPrimitive(t *testing.T) {
	vkm, err := registry.GetKeyManager(rsaPKCS1PublicTypeURL)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", rsaPKCS1PublicTypeURL, err)
	}
	privKey, err := makeValidRSAPKCS1Key()
	if err != nil {
		t.Fatalf("makeValidRSAPKCS1Key() err = %v, want nil", err)
	}
	serializedPubKey, err := proto.Marshal(privKey.GetPublicKey())
	if err != nil {
		t.Fatalf("proto.Marshall() err = %v, want nil", err)
	}
	p, err := vkm.Primitive(serializedPubKey)
	if err != nil {
		t.Fatalf("Primitive() err = %v, want nil", err)
	}
	if _, ok := p.(*internal.RSA_SSA_PKCS1_Verifier); !ok {
		t.Fatalf("primitive isn't a RSA_SSA_PKCS1_Verifier")
	}
}

func TestRSASSAPKCS1VerifierPrimitiveWithInvalidInput(t *testing.T) {
	type testCase struct {
		name   string
		pubKey *rsassapkcs1pb.RsaSsaPkcs1PublicKey
	}
	privKey, err := makeValidRSAPKCS1Key()
	if err != nil {
		t.Fatalf("makeValidRSAPKCS1Key() err = %v, want nil", err)
	}
	vkm, err := registry.GetKeyManager(rsaPKCS1PublicTypeURL)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", rsaPKCS1PublicTypeURL, err)
	}
	for _, tc := range []testCase{
		{
			name:   "empty key",
			pubKey: &rsassapkcs1pb.RsaSsaPkcs1PublicKey{},
		},
		{
			name:   "nil key",
			pubKey: nil,
		},
		{
			name: "invalid version",
			pubKey: &rsassapkcs1pb.RsaSsaPkcs1PublicKey{
				Version: privKey.GetPublicKey().GetVersion() + 1,
				N:       privKey.GetPublicKey().GetN(),
				E:       privKey.GetPublicKey().GetE(),
				Params:  privKey.GetPublicKey().GetParams(),
			},
		},
		{
			name: "params field is unset",
			pubKey: &rsassapkcs1pb.RsaSsaPkcs1PublicKey{
				Version: privKey.GetPublicKey().GetVersion(),
				N:       privKey.GetPublicKey().GetN(),
				E:       privKey.GetPublicKey().GetE(),
				Params:  nil,
			},
		},
		{
			name: "exponent larger than 64 bits",
			pubKey: &rsassapkcs1pb.RsaSsaPkcs1PublicKey{
				Version: privKey.GetPublicKey().GetVersion(),
				N:       privKey.GetPublicKey().GetN(),
				E:       random.GetRandomBytes(65),
				Params:  privKey.GetPublicKey().GetParams(),
			},
		},
		{
			name: "invalid modulus",
			pubKey: &rsassapkcs1pb.RsaSsaPkcs1PublicKey{
				Version: privKey.GetPublicKey().GetVersion(),
				N:       []byte{},
				E:       privKey.GetPublicKey().GetE(),
				Params:  privKey.GetPublicKey().GetParams(),
			},
		},
		{
			name: "invalid exponent",
			pubKey: &rsassapkcs1pb.RsaSsaPkcs1PublicKey{
				Version: privKey.GetPublicKey().GetVersion(),
				N:       privKey.GetPublicKey().GetN(),
				E:       []byte{0x03},
				Params:  privKey.GetPublicKey().GetParams(),
			},
		},
		{
			name: "invalid hash function",
			pubKey: &rsassapkcs1pb.RsaSsaPkcs1PublicKey{
				Version: privKey.GetPublicKey().GetVersion(),
				N:       privKey.GetPublicKey().GetN(),
				E:       privKey.GetPublicKey().GetE(),
				Params: &rsassapkcs1pb.RsaSsaPkcs1Params{
					HashType: commonpb.HashType_SHA1,
				},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			serializedKey, err := proto.Marshal(tc.pubKey)
			if err != nil {
				t.Fatalf("proto.Marshal() err = %v, want nil", err)
			}
			if _, err := vkm.Primitive(serializedKey); err == nil {
				t.Fatalf("Primitive() err = nil, want error")
			}
		})
	}
}

// The following keys are from:
// https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/Digital-Signatures
// Publication FIPS 186-2
// Signature Verification PKCS1 v1.5
// Only keys with public exponent 65537 (aka: F4, 0x010001) where chosen since golang rsa/crypto
// doesn't support other exponent values.
// Precomputed values (dp, dq, crt) where calculated from the private key (p, q, d) using rsa/crypto
// to avoid recomputing on each test.
var (
	nist2048PKCS1Key = &nistRSATestKey{
		n:   "a911245a2cfb33d8ee375df9439f74e669c03a8d9acad25bd27acf3cd8bea7eb9dbe470155c7c72782c94861f7b573cd325639fb070e9ba6e621991aefa45106182e4d264be7068035595d7549052989b3e7fd04cabc94012c1278a0ef8672b1a51dd1a9e276816ba497dea24b4febe3dd8e977707bcd230ca6fb6f8a8bff9e6ba24fbadcd93f00126b19b396a38e6ef86d18fef945b9154c1963fb488c7025953511f86d05638bfe056493730bc6778446e59cd3c5c3acf07a0a3a64943793652f10e3292aa7a6d25a03181cc6f6ba0658d909e59ce2a02bacc9766fd8c4fbd4ed9c23a866844b8a794d49e505f9f944870a71aadbe5338039825c2dff81af3",
		e:   "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010001",
		p:   "bf96de108963b5113399b664765efe046e2dafdb70d6e5e29dc6ec89b789b059348d74d89129c7ade9ddb404c6dc3a3437c7fc9f23bc38dadc8ffd0ff757999f5c2d510b993056147ccdf421e03d0be2c74ec333a9677c430cc604f5550d0d86defdde71488e3db889c699a5cacb44dcdae2f3cca38695e783e6f6250827efb1",
		q:   "e1e7e33618d1b64d6862c132e4b1cd5fabad20ce62bd97bce2a3f5ad2da67bb0a7f0b9e48335a33b7b95e77ec4c47e91416881f9f7c23f9bc1918cc644335c74260e90cd7b2e0fed802f19e78c5ed80a431b38630d82f982c74a0381b8ecf943c60810fae90574e216357b2535002316d9529cb56420f3cc82dea37cb624e1e3",
		d:   "290d117f97d672f3647c2b24402832b153d22a25820567688645ed95ffa6e38d116347486ab4b485c27aef4962653bb60257ef82256785a1d3d52aa0e0b94c37279dee7bb308688aaee98108de6f1373ed2c12429c9b8770756c12c03908b346b129f963bfaa38a8937190cc656f057ef1a812dd0312f51285c4f46f9241f3028ea6a61db0e9255976469f5d5542ced55ee2d6f4afe766c0a70f49871d369dd8f3a82a7141639efd4a1f4a4009821c3c2b9f5c5f5eef99a5f00fbd8bc8191a3654e8f8d8ce12d90e5ff2a4c530b76306c8c56e0549a6f277ab2af3a60cccbf4bb4b2cb47f04f211f8b86aa653bf6913f3b5ed190c51b5958e40597a2dfd30061",
		dp:  "bce35c3a8789d3098b8b1fa4ba837b03193157f10cb6025dc35a4cf896085ce2060af4c9538d127de7559a571f4c1ee23ea09ff2b203af36304091a9fd1cd3aba6f052b811a6f3272dc8cbc9de4fb1793b30ef08ef1ac50b41fbb505bf7da7f971be6f61d6bbce243349a7502ab8ef42a357203080847f248b09d961b741d071",
		dq:  "629669813d59a03eadf4932e1bc240c7a4cb7c8ab56ada62b3622ca07450b8a042da7ab5f05123389d59b15a9092d44d9e06f6da5936ebbd94bf6979496044d3e79be9b3d33329fe5337bb0d63242d126570e6adcbc2c21341d7da29edc375910f468bea84713e2e40d4fc3623a838a80b15d39011ef939647f2d3d464453a53",
		crt: "1261dce1e3d5d006948baf609ab5d114780c85c42b7065ddf0ea41d0d9e1bce2b154086551e425f36f46fb0da62ba7e054b95e5207ee08a6e1aa68cc611abe3c57e20a275cef95b4234b2539e1ed48e5a2363c4f2cb84178dbf6d7bf968a722ece1687376703099ccc182a30d5761b5aa8aedd33941997c63f678f4aba1c0d82",
	}
	nist3072PKCS1Key = &nistRSATestKey{
		n:   "f33d3234f13272c3b2b6821ce4805663ff2e8b0d2a47de363d97fc9cc879cc6b40f9e53aea695dc538a0d2b558498829aac327eacbcd889e172b34f90745c5d528b7e82605f1a58fd228ec7fd4b6f476f393864f48dc47097c8a780a2ecc02f748138dbd7df99c52d822a2e5154c6047fb0eeb4f49da38edcae3c32d3fde435f291f96cad1e09e1030ad7efb4944b69e074d0d7964becb3cb86238d8d293bef3030d141d14868bc21fa133e9de1115f749991cf86ef506e663ac162b2c8567ff131a6b467a6f564d6c588860becbd88970354198ecdd4f1f4baee8f8bdaf7255835385f5673625f113550b123628a0be3994d91c3a19a82e5d73448dabf684ee6794fba7a2b1afbee0287e5a11180c29ce0896795d52ac7f408fe28e8e9116fe0b61a1083f95c5227d62d5537b5040b79e21b3a8e83c225bf3efebb2f808541e97d28a2468359fc60f588e74faad611262064628a25d8d61f9d03d8b21cca515595aaf2343a759b74a6a8afeffca139a389aa281995cd18e16a9cf7b7ff0dddb",
		e:   "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010001",
		p:   "f3fcc6aae575312778d9e896acfd7c1aa4c5524f20453e8bab255363164afa7124b2425587a077fa0bfaf61b12ef3f0540dc4c9e777122a60610a53d1d75b0a5859c654a8ddfc2ff4860758bf5a6f264bf8bc2baa7551eb7be23bc06978be992fc81d890e07a3abf95d20eee3f6bbbc089985cac96395b473b2741c66bd2ccbef228432f66b906c15b19694dd786c29f06cbc17b2e6400dde4e3db85819382b3d05a4c3009f092d40d05ed5b2e0428a214e15a7aca09b47120b9ea6cb4084fcd",
		q:   "ff36fcdc519fe10c69aa0dde2cf3bc72cf2ce9a54ac063d809b523f4e5d7ddaa5413d500dc21f409ce661bf33018b748fba3966d874bf96f4313eafea9decfba71d540ae0508161a3658c4762d94ebb3a4e228c45661315db30c20fbd9e20e24c044e4f0b49e6ec80949b16e0ab07f3d32b248b39f48332cc3686df05d29c170a7276acdd129259aaf018ae3afb49b6e0ddb9e404a492863daee7be71dfb11279047794e45f399a9665796d32d5e65956a13a6fbe992b36bf4c842f5f519ac47",
		d:   "078ad6bde08572c73c5e94bdf0f1efd12da3a8fe7c035027236acd3e4ea86edd1bddd92ca601d012b7aa4e4e543caccdb49f54e35ecac7ee8b03b522a1b09957fe3ebc4d42dd96dcd4f9f2e215dba47749c9ec7369ec21571b21af638ac6f05d45980c4af0c1e6db2f70dcd738a803cb9cee7dffc3e7a735ec6c2541b270cc6b0225ef71939220f9ef35cf5c5b0dc291e237bd456333d803d12883e0694b2e891a3248ca36b838a8de27e154624fea5149857214b15ac4b4d67e0ab944ff5000552c66f833239f3d4c27a76cb14dd181d3f52a12cb4f3f9518dcb68c9db923e677d6f733febc93152c311880205a5b73ef323c07b87cd55549156b0452656f0f11a2c430924f426a22117c04dea477588fe092bbad1a4bf2a0a7b6befcffa3f91f4d308ff24515dae15897e9ab00bf755f9a366057b66f095573a9f881bc48e3711de800b3c0155c976957c40eab8834c7b7911d426fd7484e895fc8d8bb5ef7b562da7a846fd6bd013cef55ff3b11de43fe6da0c90b59dba4bb060ce4caf3cd",
		dp:  "7c2a7fd028c5e325fb52aa1344261c2a5300384b1c5920e3634db38a11a6469d9dd739fadcf2c51bf34cdc421af8b651ae186ec5967374f698cf8fc7f25e1a6fa1f75d74fb8e8c65ee2768aab971249a3100a730e64763428ef9108f2a4081b5d3db20a35a19da1bf5dad8ce5668353c5ec9b32001b35ec8794a1927296835da56d2369ec0e01897fe0c88929cc46ff70e365358a4db2fb5bcee58a130b82923e93c8ad947b5ae834bbd6075ae8d5f405ceff263dabde59e4cd15083d17b0961",
		dq:  "6a6ac44f1dddfb9a10692f35282b4db5d5bb55856dc10120f1134df5ececf0e9f7faf9034dc6fe9a242d21946ac6b38e4417373f5e7e0879235027d99e7d60c2ce7a6c68e38236ad21622c3156da54d9e873c129f516bbdde52db6872d97fbebc91c3116494a12c9684e0924e86225fc1faa85741883a38b13c3f4ab983d3402c4404461a3c8737ca7628e46585a87c1011845496b704bde2f48e7f33be6178616bc26d1c38b4ad47eef20ddd77a18039062b76b2d3ed57fbb66d1bcfb41843b",
		crt: "9779d59e838e714e0f04fc936d40863b2bf492f446eb90cfe58b27205c2745e59dd7b5becd7de1f01f1d5a5b1d40e4d2281d668d545d4efc0bedaf5e7cdb4fed310661403f5f31e0e8ea23adab382ea09e3610c7548d0ed835bc693206fbee91a66f1ab9c2c80bdda3c26e1bcfd78bbf0f5fc13d646922d395848f27f5316380b196d4ee422e77309c06b9439216d3fff1c762ef662bc3b683e05b5c29af42fd765c7bc1b1356f1618d02ac9f36ca1637bc6651f8478743bd4f83ad37c5fc915",
	}
	nist4096PKCS1Key = &nistRSATestKey{
		n:   "b10935650754c1a27e54f9ee525c77045d1a056baedc8c1ba05a3d66322c8e2e41689ca02b8e6ec55d3331cd714e161b35c774311540c6410cc3b130e65cec325377ccf18a5d77054afaa737e65b68662327627f5d1092df98c08b60a3ba67599b1406986f441528d2f1f5d6fe5ec6b8aa797dbdb3162876b08298237af81c7004863576af572ddd66c487cf32a82d0f9fe260f8f2681613208aec55723622f50d3cb3bd33b1226d5b5b9ea2c97a2c59054e31536849ec2f0f2597c077e621ddea0a22ddfb1df925c9f1941cd431afce0398d28e736cfeab3dd7f062a65a2a4c1ddca1f32afa03b4ddfd8b7ca40cc0ce2ed42229d753f03cc6d8bcdca76ab7c2703c5ddad08aa9bf9a27740a8b23168c6b55917bd3d5c1c057c34d1efb1411da51ab745519bd92b9432fea8fadcb9a70e5dc3adcd3081d3333507b7b998886e988296628dd7265e64eab557712556cc492377f15a078dcb620a6e7f051a1fb8754efdca3de253dd0aad4205b032659e4a4fb307f074fbde340702b5911acb34737d7834600cf2ac77f62f83ccc9ba78ff911021b9f8ad1bf421430ae0d64916944b504542c0f6263c48e5e233ef1869df1efc2ccf6f4a95e4db2de7b4cb1a992bef6573511bab4bf2cd58e72a0c235f56dfc182df4dfffb69433a5677415f35d84f5125f5200eb57868cce6b74c5833417990e318372c9239a36dca1a0b28809",
		e:   "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010001",
		p:   "bd4e8bb7fd7ef1e39d71de06b0001bdadcc81b0edf2226e0d056b7eea70b2249000279cc1c04b1ac2919014fc3fb8b62baca3e261601fb0a58a9f67f03cd60085b2d43906d36ad014f321012a9bde9617478a0c10201afd53f2207de3648afd1d737afadf7fd2c0b9824d4f66b2c7dfe93390888ac088c680c27b1b2486659ccfa8986c8c23f78f18b5815a410328e629e7440221bffd8ec4722bba3420da5234f898f8cd7e6d7dcb1349bc4a0b665b41d930e3957cfdc88797aee5b2b27dafb5ba0949e3dd892f490212dfd249f4b1d99fd3b72695ee0652997127f0b9b417fa8365ba9fd103b978309d9baa9d401902cc107cb8d2af7ce04660900e3707ab3",
		q:   "ef67f69838735c055145d21fccb42298642177fe3fadc39070a95e4fc04ff058aeaf9070b4eb2de1cca72d8533bc55206d2ce9f2895b148da67c89e5b6496ba682f76bcaef69306a7fa4fbd41a838bdf0fab3e7b56c27a8c18dc4bf970364dff7427cdcc6f532b49712282370a718b7d5287bfc02c4abc35ccb2eab3777f5e0d8a27ff9ebe13e725aa0a0cd48aee1fa33ea6b4ea965ba42fcce7af3c528a6675cedf4969640f2ca73345dfd322620df9dcf16520195df8232061e2bc89c12de24838f255e7b1c17713ba435d5a351e263350198b3fb881b8ce0acb5aa58b7afaff184489d167c9af21e40e2ba9fa69b44a3854329385c97df0de24dc283a4053",
		d:   "25e0b881e32da938611b4156525ce24216c168837fa84479ecb72207e9984adb6eb7393bb3d607b1469d9b7c3f4fdbbefaa4b0218850919a7d66a954b315129c39eb99f7dc08df5c4c8c90968f3ce37b66ee184ef3d485f83d308521aa2649d28c319eafa2aec87031a1ff5d7e933ca56a2410593425fb865981b7976fca021b9d7c3198312fcfea5d0093a62b4a7c49a985c005c3a7ad816e270b25c507fc36be1c4cc0a07cb7c6fa130240062793b18047189aa5e79b16fe80a6955191f5910b701bc1aee6dcd5cefd57194bf54d8e208ae41202744190d5ec8bcc2f977f11461a5cb4306fc9b73afff2863a7b580d454bb1fb8dccb1cbef27945109a8f5a3d2b1a32566aa4e8c01a62a1d735117ff5a6a3cc7e70756e7df10e97ee75c5f8ef89fb0a97d7a35698069f59a9f365d4396ab9a764c2fbefb840faf5f57737801b73ac6f9f524167b4f3a567aff999a0db10d55d82155720a5ddc63c35b6a632a3da59c16bd0c143c437661dcd339652ae42f54f8b2d8e52672613772abfe8cf0d6ebbbccc764b51b3eda2ae28d4ba8747a430ccc32c73baea63d050b86210c485ac9554606070764cd06b423efdda4059fc45ffd7193f7123d14014d5bbe5b542476e7bfdc4905731a0d9987fe4a68cf6077c3df63778af08a1f4eb8f00a4a8e03aa8726f43fa829d87c2d0a32e16b47a3f0472a6368ec50a144234c802e6919",
		dp:  "0ae4891f962386d19d0e9f42ed3fa45aac978b0f0901d310de8c0edb599b4766c1ec628bbf14fa1038f12a652796c2c7748e0c936e72c0ba30addef42208e03cbada58e7e790dcd5957400fec1eb9e912ffd7cea7e2e10ab098df0bbf58dab283ce50463d3402b17a3b282da87023161c3a0e57fcfbe522dee7d1e396ef70cb5c1b8c61ba929b3d0da3ec04807729144d56f44fd7175004b60307c71816c7d9311918dc401ec53816c64e58da3ddbaee69413bf14abf3826562f1fa5f94ebac7f9d6bc967a628ada2daceb1384d6f1a08b6ac9cfe486440d2e1e763eff30f8ccdaa5fe1242f07b2d55a9ec70543351bfb5038a6a48fe2ef218c8b23dedd85c07",
		dq:  "9bf8c68e8b9094ae1e31f7e0a1d3e60a148a3d8bd65ed5df5f96e88bdac5f9d73d0fc271bb5cd10a9ff376d3a64e17c3c57d1279e20505d1f75a81d8b7b703bc7aecc93c7057bea453bee01662a3bb57baf49d036c15ce13420b1c30496c07cadb192799fe19584543c0f0c6fd35d663f285e0664a34f283b6760634a030c9ccd66a92be1026155cd37832bdb239cb40e68b63a8c606b4643401e987ca5ac2c013e42306d79a8f43eb42a5bcff5494b869ba97609f463a68602b85b5c1a5aac816b78b226e8dbf765dd2e71a85afbf91b1b288c1d0e4db16d49df1b87fcbec766405a2798b852bbfbebbbe83b1fd242ac2840a4edd0fb7a3266f03e2af0eac63",
		crt: "87f4c4ddef9c241eae1215e92f30e2252519ac18c6cdf8906bca21627fa7288bab9a0efd1ea6fb8562479bec1de7ce7cf2f86cc862df35a3766559a87a4dc2a12d20f30815c68bfdee87beabfb5cce965f5fddb0ad59153df8bce3acfa279aad0202f94f2a9b48049e8a3e5a1af82d63269b5d8ea864b8b1239d2b5a74496a116b23070932f7a7f4b13140e17826bfed5004f7247dfe1a8a0943b9f6fc0a856fb96159c61a2584380aca3fab48b892639b80f089b35b65182a973878b1b16cde5c2c0b0bff46884b8793aa8564d06eab99f6ef407199b7477f8b811ed1434368895cc5ffe2354a04023e9ba0598da9838db89adcb9986c37e805ff0b083da119",
	}
)

type nistRSAPKCS1TestVector struct {
	name     string
	sig      string
	msg      string
	hashType commonpb.HashType
	key      *nistRSATestKey
}

func (t *nistRSAPKCS1TestVector) ToProtoKey() (*rsassapkcs1pb.RsaSsaPkcs1PrivateKey, error) {
	e, err := hex.DecodeString(t.key.e)
	if err != nil {
		return nil, err
	}
	n, err := hex.DecodeString(t.key.n)
	if err != nil {
		return nil, err
	}
	d, err := hex.DecodeString(t.key.d)
	if err != nil {
		return nil, err
	}
	p, err := hex.DecodeString(t.key.p)
	if err != nil {
		return nil, err
	}
	q, err := hex.DecodeString(t.key.q)
	if err != nil {
		return nil, err
	}
	dp, err := hex.DecodeString(t.key.dp)
	if err != nil {
		return nil, err
	}
	dq, err := hex.DecodeString(t.key.dq)
	if err != nil {
		return nil, err
	}
	crt, err := hex.DecodeString(t.key.crt)
	if err != nil {
		return nil, err
	}
	return &rsassapkcs1pb.RsaSsaPkcs1PrivateKey{
		Version: 0,
		PublicKey: &rsassapkcs1pb.RsaSsaPkcs1PublicKey{
			Version: 0,
			E:       e,
			N:       n,
			Params: &rsassapkcs1pb.RsaSsaPkcs1Params{
				HashType: t.hashType,
			},
		},
		D:   d,
		P:   p,
		Q:   q,
		Dq:  dq,
		Dp:  dp,
		Crt: crt,
	}, nil
}

// The following test vectors are from:
// https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/Digital-Signatures
// Publication FIPS 186-2
// Signature Verification PKCS1 v1.5
var nistPKCS1TestVectors = []nistRSAPKCS1TestVector{
	{
		name:     "RSA_SSA_PKCS1_2048_SHA256",
		sig:      "794d0a45bc9fc6febb586e319dfa6924c888594802b9deb9668963fdb309bf02817960a7457106fc474f91601436e8954cbb6815350b2c51b53c968d2c48cc1799550d5d03b41f6e5a8c3c264d2e2fe0b5b8ff53fdcb9dd111c985cb488d7086e6548b4077ec00721c9cb500fe07a031c2030e8ad1dd0112c34ffd9091d77a187aac8661b298eee39eb615f9715c4c48a6762ede55a466ec7f3cdb6a937cfc80188a85d8f8d3a2a80b199ce5e6375af8f02f06d706a34d9cf38318903965db54aaa7d3fa7a7ee58034cd58c8435739c8906366e2ddba293f2fb2c15f07fa4951014471e7f677d3bdacffc4c68a906e08d68b39f9010746cbacd22980cee73e8d",
		msg:      "6918d6328ca0a8b64bbe81d91cdea519911b59fc2dbd53af76006fec4b18a320787135ce883b2b2edb26041bf86aa52c230b9620335b6e7f9ec08c7ed6b70823d819e9ab019e9929249f966fdb2069311a0ddc680ac468f514d4ed873b04a6beb0985b91a0cfd8ed51b09f9e6d06da739eaa939d5a00275901c4f8cf25076339",
		key:      nist2048PKCS1Key,
		hashType: commonpb.HashType_SHA256,
	},
	{
		name:     "RSA_SSA_PKCS1_2048_SHA384",
		sig:      "80d7286710e5f165eeb63d2936e8e313ac5999bd297d35590c2b6ffaa4b7b7ed30003f0b83c1d1996c8593a37bc5d7b501a3d126ac6124779a23718497002d9dd2ce891b83d185e333af05460c6deb65a509640f775a0d3c70e55112c2e4af19f4ccec7af9ebb34226164f1b47d50b8ecc1dc3e0fc09aa15abfce5aa3998b5c2b1fde261c35eb43220f0d64529f723801d7faff841faba8709f6ea7751f30428dfc58045c84995107ee013ca4a84f65b99adde1abdefb5428f834ac8da04dafb9beaf1813f73a4bff2ec94120e3a702aed1184c387ebda2abf1959970724299b9a05f4ad313d91beb5344fe1fe13b3fc3386c279f031c77d74bdc9bc97e22455",
		msg:      "752fbf49ae63c7853b3ef6f52ed324e53867925bd5d4c49dc42b93f3ba9d7eae579c4169593da98f10e1a61e1214a2aa2fb511a4a75849dc9be89445c29184f85ddc877c6d1cbb45230a047a98ac5bfcbe7b69a397c454cba44fd90fa13f9b546f39ba0a52c8a8ae5c0038932962f8e3cd00c1e00be28c70c8a787d9be6f69c9",
		key:      nist2048PKCS1Key,
		hashType: commonpb.HashType_SHA384,
	},
	{
		name:     "RSA_SSA_PKCS1_2048_SHA512",
		sig:      "25b408187418c512e7d36eac17edc64999e94011b4d5088ab926d29e433a69e24ebac43146a1371635fc78c3d215a66ea46d0a734b1607fdb9c3848a1404545ff60582abd579d978902ed399eb5dcdfacde0ca02145480246e1a22af5ddca7080aec216895d3528a8756e0c1a2059d392f87576fe896e411ddf02bd6be81ae2a654e0a15542a6b533b776703e2057b01ad02f5430d97c691f80219e46319de527541f0bfcf0b4e1b510059fa20779eb44b1ef293b7a8318447ed25793037ddfd1877cd98514c81575613f36d946670f632779eaf629a593fe99110e781cb38101a3cbd54d7871983dbf868a00cfcb17bd330309d43b8df8d4f05eb4c43649cdf",
		msg:      "5cb7a0a74095a6f284a13d4392aac30a73a9211df0520bf2f7e9831240579fca2f7d8d24fdc8d4161306dcf8b678b13be92804598f7c7308d10c0ab3bfb1092a3adee799113498b76a500c3f64e8f8a4fa16d8012bf3354e576823daed410ff54383b7edc5007a3d5228d200e3221fac6e1ca6fc0adfd92e53a6d96f10303994",
		key:      nist2048PKCS1Key,
		hashType: commonpb.HashType_SHA512,
	},
	{
		name:     "RSA_SSA_PKCS1_3072_SHA256",
		sig:      "2e4d98c10e126e544d2b74bbcf0a4f03f081d4725a6661c0683d3612b01ddb2dd6f0391ef3679f39dc0785b37ac275f0d6841ed3a44ff7f6a407a085129a164faf63ff2aaed18ec6a5f7d27b48d017a50b24c8c4859ad2bb680ace5f3af57f2eac2d7337c0dd7403ffb2e8bac69dfdc98e62a07354b2fc93d03e499ee2d126647edaba094196b693e98cb98ad2817ba3f7f522c8f786b6ef82632ef5a00d5d4f42db6d26709909ca751aa8174037c924628852ce78e2829493d6c741d3558adcf713734697754e55e7b3bea0d8717da8aba2b2874527a0b3a8d2e1433344dd6bbaee1ebc7fa352539d94c6b45f915c6979b8e18be8934d28d770806c6ff893660dffd0e948a8cce11ac870507f88c1f86caa875ad721326dcb4f0d5ecc2d2538c4fabcc6c756ce4a59bcdafc44568787cf2bd9650486da8c85fd0b87794547e179e498cb6a5b26f71f9987d703f2d53418411c1f9a3a2e6705637b7bbda9660641c0eb037eb432b2d7515d1ffa99175cfdb8a2a4eed013b947faa4bf1c3cbd59",
		msg:      "dbbd09ff7b1c707c2bd52014adbb773ceb146aa72637c8724f5ac39fb5a5acc4e18bfe04be599e3ffe0f6186b870cfd2565527f5ae46a3d06f4bfcc7bf00317222e885959e03c6531da3d59e127b63f25ff9f94377d63b34bfeb6d893b4636df667da49a61427120503885450205bb05d0a9e879c70e1a0409df1dce709e4473",
		key:      nist3072PKCS1Key,
		hashType: commonpb.HashType_SHA256,
	},
	{
		name:     "RSA_SSA_PKCS1_3072_SHA384",
		sig:      "879c4df9b66227ce30e6403b620a488c72329b400ec67667a600bcfe3d0ea893f3051c8076eee81e0fece30c4153552ae2b2c774888657adb5300bedaf4940d6d6ce9310a476093b3590fca889e8ead464809be4da3370c21784e4740453df999bb9f7c290ea16e4b0e4ca666ddf23c757474fa9b0dbef769b1876e1eb553ee3a1c14c201c101164d5d1e5f628a7ebaf65c0f0f27f239ff67a4fe659d347cf50921b5859d79d86f8bfd2a25eabfcf76eb606b4151516c482c74ca3e54ede03e99086e61c0708e8ad9c94c1fe3640bf811f4e2c0e62d17d593f2e86adfd0798f04616adf9367b0f77f40de77135301debb490bfc76ba710878ddf91651a5fa025c348b6066a49853d6ece7bc79cdcd8ae709a77b96701c1ba9c4a91663e3790bad5c5c48017fcfd005a1b03d47d07dd3c511aefeb4c766dd19e377d2d82329a222b18ee0899e166cfb37c0b1b3226123f80a33c096fa4ba784719c4d9e52e60ccddb6da8575e705a36dbee7d97093f830283c71abbbb85c06daa913f96dede4ce",
		msg:      "88af470625e6b5be3358cf6a8698a5655ef321838f044746df83bc55b05e8529df0b120aeb1c7b3a5a1409705879f887a22a7b78a2f30186db5fb7b888cd4e8c80c6feea5d8ecb57ddf9076b8980188594947bbd0533091a19b87906e2f727fe3589138ec3652d7d86b0d0455fd78cc5fdda283a00ebe76c5e370b25060498e7",
		key:      nist3072PKCS1Key,
		hashType: commonpb.HashType_SHA384,
	},
	{
		name:     "RSA_SSA_PKCS1_3072_SHA512",
		sig:      "aa3ee99d39ad0332ca48deeb68b5966962018906f1e2e97d0d711df66e600fc875faf8da141212ea9bc49b2934f19bcb26f819b3633381b23f74f0c1d486c8fed6f6c17cacaac222e55c8c534ca2cb3921ca6f0cc19d045fa5456b4ffbc496d0d3079f19d93bba5600048b783a905abc3f30fe4b33b057a203b5f9d01254bdeb02896cc11b713fdca55e3ecc67e243fddf19130e2f3c79bd984558feef0fe877e071b0a13323e700de83244e2bcc09a602eaa06bb39d832d58e30450dcd96b30052778c07d4b209d5929bb6cc80800c95963a24bea449189301b50b5f26a899739dd0a4af6eba05e7e625c96cabda3beb2e4b0d11ccf72252b2d524d76a104a6dcef635517d78f248c78837422ac900557e1671958116500c673e2fc9a08e40d4eff8d44146f43fcc5f4086d276ba026e9953425a11b7be0036ddba0648f12424c3359cd8db8a0490b1bab3b35d3550840b4937ad1986aadedab74fcab27fec7561ae2bbcbb16d28d173efdf049fa8a1daae66db51f4c03fc91d1cda85d2cddc",
		msg:      "112b7aa9fec5c7ac703a49c298c4e29586083296f79b099e6ec422d586840ed486d36e06362d6554f14d4d01fc39a9d2167e5b7350bd18161f66185db0c4127a7b3a67951bcc9e6d5de010439746e4f43b773e65ab1ab4234fcd024be621fea819e6ce1c56aa5841db7cfa4f11f67b411c7a4233b0bbc60f267f4668cfa4baa6",
		key:      nist3072PKCS1Key,
		hashType: commonpb.HashType_SHA512,
	},
	{
		name:     "RSA_SSA_PKCS1_4096_SHA256",
		sig:      "2df1e58e7491739bb027c6315a70eebbcf37b8e5958df07578a589a47cbaf1edb23ff2e676f2f273a1cc0babd22e0bff874529cfd6479ae5c7250f06579eb212dd3f4058c476abae8e94c89afe05746c3aea93155cf03195ce5f4eced399d2b61aab7f4060b69844cbff6303d264c4755be78af001d125af461fececad8f46a9c4b07420ca63c4212f80a751fcca6a4737684543fcf07b39089baa9995394766f69239479e7c9778c644e022dd4ec7e07a769aa75db2571e58a5e0ba1e4377e9677092bc9dee9d9dbb448441da8f4385b4d4f8ccff4b3dc3c3c3ac8ba11a6ce8caafa930108ba3603c5b0ef65a02a7afebebf605aa88511513a69b3086fdfc25c588c4d61a06219d0d5643410d3ae4d78b2f695efe4e0b82161c53bb9d4b8a83692bb16de8da18b4a6c2abbd0f6b0e24229077fd6c3bca918bc9d9f4518598238df0c925f8587fff0852c44e8107ccbc1ce6a9be3b0941c3b28bb03c87eeb959d719dba9a64a338c7b9931cdf6bb169686de1f8de0e1fa74d03419d164f2c8bd2030562705d1470415e48144181dfd31cdd4219b5d22f9a4c659923cf5c4edbde18e8277dae11264c11423c5481402e80af223f0c4faea0c2c7aefacbf513962c2f16af353ffae1414b408f726eeb946d7c4c8577e72d8f1d49ae2301cf70abee46d286a6fac1b888c334538abb3b830fae595bbb19ea9dce46a343da031117c",
		msg:      "8f937d50d24a1a6ed858d2e3de56e5c23b917d5a936c87b84effc06d48041391caf42207ba6d23030ed7edca864752b99ba3b089b308c3d19668bdcc2578995d4ac9ac502b347de3a37cd685f22f1bddb3cddb0e0f2ca53a311b1d45f9464edbf55a42b48d69d0167d8fb69c89d6e8376b57277211a2d4fa0560075d2d37dc12",
		key:      nist4096PKCS1Key,
		hashType: commonpb.HashType_SHA256,
	},
	{
		name:     "RSA_SSA_PKCS1_4096_SHA384",
		sig:      "0471456bd38ff2a5adeb19b73c35de60f07d7907479f9e6d5735dca75ebd3ef499194917287ae0c3334a5b97f2be41598917a5d880b3d021c61a7acfe9083441661f56fb984ec6717986c558a10d108fac9e00bbd5adbd817a7684edd424e612c8a7f60ff1c8056067f0eee1c6ce3a4ceb6c27c735f0fdc93cfb521b529e1002659e6fe9cddcc79c218a84ee59b7355a43b47b5c4ece8535e0874cca866e3981dec3d1996d4dd05afab27bb5dae9d6ac9dc39e957329eb273254c4e7784a29db26696bd0ff872eede9fff869c35487643755d9cd5bae01c7858b123e4f9688b1d2607f349d52c828dd6d76ff41514565564d39038814841a0441c232411c8afcb15073739f5d5c537138b9bbda60bfd2cfea2847678ffbab73eb02fcaba9e4cabd7768bc0c3a6009dd78f02a8d791f5e1e30d7358b5a642cf0a1a838b954b76a15386109926595b2862de80ddfea98e6218efb925cf5d6434b93045cad5bfd1af36e63a98c14b8f5c6974f04e5e52243bf7cffdc8cb9c0a35fc3250943d07037b319cafef02a2fd21c39aaa3da9f171f1e9c9613ff97d3a6770e7639ecbfa7e47804d8833e8212064d091e02801869bcb2bbbfc2be5d21b2da790ddd7973b6f5b9d6c763cfa503c6243851461490dfab31cccc6621fd91fc1ae28b4b1d393cb1e41d397852acd98fa35b93b6b4dd92e2d5fac7665d8c0b3f7d03ad3048b6854b",
		msg:      "450171e919ecc10bbf1d05f41eee02eab8eede088a31263433eb1652593d14b7494f7de1dd9fa465a39918283b6726d2010a9f80edaadcbab72afea43e007a782a44d633d006ad8f57e5f93219dd92254c61f187e2aa3a83ad4e7a7fc7142c9631070349bac9e371232a307880f94cc9e11b5b8532d94a78607e0f4bbe2232fb",
		key:      nist4096PKCS1Key,
		hashType: commonpb.HashType_SHA384,
	},
	{
		name:     "RSA_SSA_PKCS1_4096_SHA512",
		sig:      "6836dff1bea541916b9ccce2695e921ff27a737ac54f4a5c3b2facee80a8dd3bbfe86c93a1af8da5c6b3a92c445dfac7e215fa9f3d67c9589dba858a223f326afeb8f5d0f92f28ac4e3671c22b5b4e0b4266f776aca928bb0309929f2c452b62d462675cef09388e5720cf0cb99351d44059790720db82ce014d7e795826833284bd4205c64e1330e30e09ff6220f62c013c117ace4f4286cd46e52694c4925aba12a5278e47de910dcdd820396febe5179bbc6ccecdac1883bd408530bde92e93c49db2c6fbb42e9705f29703763b21a8172489d2831889bb060505040940e60f7c5cb9f58327c3d3f7cf7e18ad60e877edb65222a699d4acdcb358fbc87e1e461468cfdc82a8cd7fb1f82e05378737f4aa741a63ddf6039b23e1aa19d94e7087915899685add8a8da8f64a93707be0b6354c8e9a8aefc7484bb45cd0beca493a4a0aef0b6aaae801866b905683c582bf39f9cc0768d880c6e4b331da86506b298c180cf95fa45e532483c55544371468088b4e378f37976c397e09f89081f0f0b6f4ba3be6929957f55f14a88f6beb456b70e6fbc6227e98c1e8a4a6f734c9080c13ed58bcfb3456cbbc217653835000f54956d839d4073571d8a42fa2294df1a747e88af53a16df1834203009cccd6d61304739872ab92be79a4462125ebc8bba909ca2b4d91b9e520d6c681c2f92070f156e31a6875122993e1d94fc3568",
		msg:      "42c5ea617a25f019329ee172e4932485518dabd01983249189597473b4a6616cc5ba8ee693e0ad1d76e0f0c85ac8c0fb11ecb24cee2cb7358f7593b9fa8b904aec0573eb6d99af92a899d9d0fabe5cb349256eec9797422dd60d7fd5fe73f2cf5ead7fb72fd85e3f6fd284d2edfc5e77a03ec5f73c4c2f420728220fe9e9efc3",
		key:      nist4096PKCS1Key,
		hashType: commonpb.HashType_SHA512,
	},
}

func TestRSASSAPKCS1VerifierPrimitiveNISTTestVectors(t *testing.T) {
	vkm, err := registry.GetKeyManager(rsaPKCS1PublicTypeURL)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", rsaPKCS1PublicTypeURL, err)
	}
	for _, tc := range nistPKCS1TestVectors {
		t.Run(tc.name, func(t *testing.T) {
			privKey, err := tc.ToProtoKey()
			if err != nil {
				t.Fatalf("tc.ToProtoKey() err = %v, want nil", err)
			}
			serializedPubKey, err := proto.Marshal(privKey.GetPublicKey())
			if err != nil {
				t.Fatalf("proto.Marshall() err = %v, want nil", err)
			}
			p, err := vkm.Primitive(serializedPubKey)
			if err != nil {
				t.Fatalf("Primitive() err = %v, want nil", err)
			}
			sig, err := hex.DecodeString(tc.sig)
			if err != nil {
				t.Fatalf("hex.DecodeString(tc.sig) err = %v, want nil", err)
			}
			msg, err := hex.DecodeString(tc.msg)
			if err != nil {
				t.Fatalf("hex.DecodeString(tc.msg) err = %v, want nil", err)
			}
			if err := p.(tink.Verifier).Verify(sig, msg); err != nil {
				t.Fatalf("Verify() err = %v, want nil", err)
			}
		})
	}
}
