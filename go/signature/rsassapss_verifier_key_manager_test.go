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
	"fmt"
	"math/big"
	"testing"

	"google.golang.org/protobuf/proto"
	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/subtle/random"
	"github.com/google/tink/go/tink"
	commonpb "github.com/google/tink/go/proto/common_go_proto"
	rsppb "github.com/google/tink/go/proto/rsa_ssa_pss_go_proto"
)

const (
	rsaPSSTestPublicKeyTypeURL = "type.googleapis.com/google.crypto.tink.RsaSsaPssPublicKey"
)

func makeValidRSAPSSKey() (*rsppb.RsaSsaPssPrivateKey, error) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		return nil, err
	}
	return &rsppb.RsaSsaPssPrivateKey{
		Version: 0,
		PublicKey: &rsppb.RsaSsaPssPublicKey{
			N:       rsaKey.PublicKey.N.Bytes(),
			E:       big.NewInt(int64(rsaKey.PublicKey.E)).Bytes(),
			Version: 0,
			Params: &rsppb.RsaSsaPssParams{
				SigHash:    commonpb.HashType_SHA256,
				Mgf1Hash:   commonpb.HashType_SHA256,
				SaltLength: 32,
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

func TestRSASSAPSSVerifierNewKeyNotSupported(t *testing.T) {
	vkm, err := registry.GetKeyManager(rsaPSSTestPublicKeyTypeURL)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", err, rsaPSSTestPublicKeyTypeURL)
	}
	keyFormat := &rsppb.RsaSsaPssKeyFormat{
		Params: &rsppb.RsaSsaPssParams{
			SigHash:    commonpb.HashType_SHA256,
			Mgf1Hash:   commonpb.HashType_SHA256,
			SaltLength: 32,
		},
		ModulusSizeInBits: 3072,
		PublicExponent:    []byte{0x01, 0x00, 0x01},
	}
	serializedKeyFormat, err := proto.Marshal(keyFormat)
	if err != nil {
		t.Fatalf("proto.Marshal() err = %v, want nil", err)
	}
	if _, err := vkm.NewKey(serializedKeyFormat); err == nil {
		t.Errorf("NewKey() err = nil, want error")
	}
	if _, err := vkm.NewKeyData(serializedKeyFormat); err == nil {
		t.Errorf("NewKeyData() err = nil, want error")
	}
}

func TestRSASSAPSSVerifierDoesSupport(t *testing.T) {
	vkm, err := registry.GetKeyManager(rsaPSSTestPublicKeyTypeURL)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", err, rsaPSSTestPublicKeyTypeURL)
	}
	if !vkm.DoesSupport(rsaPSSTestPublicKeyTypeURL) {
		t.Errorf("DoesSupport(%q) = %v, want true", rsaPSSTestPublicKeyTypeURL, vkm.DoesSupport(rsaPSSTestPublicKeyTypeURL))
	}
	if vkm.DoesSupport("fake.key.type") {
		t.Errorf("DoesSupport(%q) = %v, want false", "fake.key.type", vkm.DoesSupport("fake.key.type"))
	}
}

func TestRSASSAPSSVerifierTypeURL(t *testing.T) {
	vkm, err := registry.GetKeyManager(rsaPSSTestPublicKeyTypeURL)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", err, rsaPSSTestPublicKeyTypeURL)
	}
	if vkm.TypeURL() != rsaPSSTestPublicKeyTypeURL {
		t.Errorf("TypeURL() = %q, want %q", vkm.TypeURL(), rsaPSSTestPublicKeyTypeURL)
	}
}

type nistRSATestKey struct {
	// public keys only require `n` and `e` to be set.
	n   string
	e   string
	d   string
	p   string
	q   string
	dp  string
	dq  string
	crt string
}

// The following keys are from:
// https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/Digital-Signatures
// Publication FIPS 186-4
// Signature Verification PSS
// Only keys with public exponent 65537 (aka: F4, 0x010001) where chosen since golang rsa/crypto
// doesn't support other exponent values.
var (
	rsaPSS2048NISTKey = &nistRSATestKey{
		n: "c6e0ed537a2d85cf1c4effad6419884d824ceabf5200e755691cb7328acd6a755fe85798502ccaec9e55d47afd0cf3258ebe920b50c5fd9d72897462bd0e459bbdf902b63d17195b2ef54908980be12aa7489f8af274b92c0cbc16aed2fa46f782d5517b666edfb2e5e5efeaff7e24965e26472e51980b0cfe457d297e6aa5dacb8e728dc6f58130f925a13275c3cace62f820db1e13cc5274c58ff4d7837671a1bf5f80d6ad8699c568df8d24dd0f152ded36ef4861f59b354bba96a076913a25facf4722737e6deed95b69a00fb2bced0feeedea4ff01a92605cfe26a6b39553d0c74e5650eb3779705e135c4b2fa518a8d4339c53efab4bb0058238def555",
		e: "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010001",
	}
	rsaPSS3072NISTKey = &nistRSATestKey{
		n: "a5f3da0aaf54b45f99a5d7085f213c3721cbe7e83b3e6c3fe0f5a84c7e387ba513392c28a9010d3b618c03847e6b11bbbbe4d5e47fc97ea696250699e96ecd911404f7b806957038a68bb59a520f2d90182d183e035204a914e6ac03c2bc6d3f9d7856b25f9041b56df310de3feb30aa468a0668a1e5da9cdb185956caa5d75e1cdcac2db823173495619105367231b7f2de7528a8a79ec9fdbbab601178a204a5aa4e19759eb16ea4bab87bf48bb1790f9fc6eb4d5674d3fbc11b922558d4e568e454b26a7178f3e147beb0c8ca6ecff5e52af248ac07d6a189393e17232adff2f7423f56b94b9a7d61fde23a9558ac7a3bc7c06748a5da11759f92baf4e386bb0212565b5beecf31d063cfab71af896b3d734750d9bca07343bfb3c28645226e9dad3070fc247c71c078e974934941000a79d01abab14d21f5e608c4e4d13deec1aef298e1247c50b47bfee6162f352f41cdba8628d1d628848c876cfb102dacce7fa160c04d3aabc8667a142a710b7f495fd350c4862a653d15c33d9266fd",
		e: "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010001",
	}
	rsaPSS4096NISTKey = &nistRSATestKey{
		n: "d7e8df622c35d46a2b92aa4a4167415178f57aa2b14f996008e41244a2c6e4e39e897579fa4d4fce60199033ee922c0f09fb8fe6572eed3a17a3c7a4ee33c8a715b6185200735c4dab77cab436b30b4d7a75900da2e87c823f233c45cd074db5805e70d582b31e3532f55aa73162302298c1c14dad186aa558c88840b04d8ce503a8a766089b66c1b0b4dcfa609e8376dee4913dfff6c3f8dcf2e962c7b72c867f67ad2b2750e920ea19ea518ee6b9d2149ff730afbeadae29b1cca3b73a61e867a700c12d3fce1b10f56b3611e4c37fe11042cf4230d7d966e5d1cdbc4e53d7049cd7f5066762db27193560f842a234f9d6d018f6bfa92a36d90c4b695e63e1ff8af82933431443a98dfaf17e780038f8cca2672ede3529aafe1d38ef73a5939c8664b3f39b0f45207cfe862f7059a8d36dcaa19588c1294e9720bc72474717e9924d1ab206aa16bf09a3dbf6cd6bdbd093870553bf6a14ea71bc24f892977d0f2adf22673813f923228fefa114c3333a40e86cd97f64bcedcaf0a2516c4a11cbd7ad2898b684f39b15435136c13e0aa1866d10b59c0a5b6338bca491daa62cf22e91edacf26cb6a3e6a9a6ce9671ef4e07612de935a9b0cc0ec437c6f7a23e895aac5708ebd7ef9d222b70370fcdd44cb8a1caf6f9009ae6fe6283e5508d5270b5b052fa7901311724f418e8c65fedfdfb9ac51f2bc98c30c909aaeb3fbe9d",
		e: "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010001",
	}
)

type nistRSAPSSTestVector struct {
	name     string
	msg      string
	sig      string
	hashFunc commonpb.HashType
	saltLen  int
	pubKey   *nistRSATestKey
}

// The following test vectors are from:
// https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/Digital-Signatures
// Publication FIPS 186-4
// Signature Verification PSS
var nistRSAPSSTestVectors = []nistRSAPSSTestVector{
	{
		name:     "RSA_SSA_PSS_2048_SHA256_10",
		msg:      "81eaf473d40896dbf4deac0f35c63bd1e129147c76e7aa8d0ef921631f55a7436411079f1bcc7b98714ac2c13b5e7326e60d918db1f05ffb19da767a95bb141a84c4b73664ccebf844f3601f7c853f009b21becba11af3106f1de5827b14e9fac84b2cbf16d18c045622acb260024768e8acc4c0ae2c0bd5f60a98023828cdec",
		sig:      "40d59ebc6cb7b960cbda0db353f9b85d77e7c03f84447fb8e91b96a5a7377abc329d1f55c85e0dbedbc2886ce191d9e2cf3be05b33d6bbd2ba92b85eee2ff89cd6ee29cd531e42016e6aba1d620fe55e44480c033e8a59c0852dd1caffbc2ce82969e3a9f44ceff79f89993b9ebf3741b2ccab0b9516f2e128656a5b2ad5251e20c6ce0c26a14eef7ee86458942ddbe95ccc1f67b253e43e72117f49595dab5ba423496ece12825435661112666dbae71aaffd5a8f1d58db9dc02e0d70fe3ac36a87b8eeed4f20c00fd4303f9f767d03bca1a619bbe4b08e4e53b5cb69d2ba0235063e04ca392334d9979a41c42a66ca8b9721edcf76989ba89f3a170bb2e485",
		hashFunc: commonpb.HashType_SHA256,
		saltLen:  10,
		pubKey:   rsaPSS2048NISTKey,
	},
	{
		name:     "RSA_SSA_PSS_2048_SHA384_10",
		msg:      "32a7b1479acf505db793f3ebed953f4e31c9ecad1a3479df3af31e89ae7e0387f42eaf8efdfdc30f838ee85e9d6d06139197b7b1e93dfb85c9c52dd17f12352a5c05001fc2432d1b7f39098d595ebe45eab8c721afa2a7ea5bccdb7971830d1e11338a42122af64a529e3fbf4af2cface635064893ece7d5991111c8ab5bf12a",
		sig:      "0cb375ecc34a9f36b88bf56ebf1235387ffacfd3dd09c48e872897caca60af9e386496aafd0d4b1fd8fb4714fac925edda6f34633c3bb08f7cca3d9ad8b76472de8c9f91cb7518648d368fbeb31d1a7cb39a40a7b17ee2f7bace9bd99ba08295aadd856cd6902ee6c96d5c1291dc299a7f3528a869f62fb8fbd51817ffe6490ed6e0007d7981ab12b8f4ce0d7432e8c3213fae2b81006f333714b513eba0414c161fab6ea23338567995f273e3269c44a587ad835c320d1e5ff553db4c47126680cd58293231915cf7aefb80690499243eda83f5347a300e070568baee2745b20c68688dad6e3807afcb34c72cdaeb9a571089c7f8c63d1b6ffdbe2fd13330e6",
		hashFunc: commonpb.HashType_SHA384,
		saltLen:  10,
		pubKey:   rsaPSS2048NISTKey,
	},
	{
		name:     "RSA_SSA_PSS_2048_SHA512_10",
		msg:      "35a37946e52678ee378f5f176838ef08f3c21392b1ad204645255be5b71fbc185fa5f161056ea65246b204fd393c77ab53c1b5d18870fc3fb3ca9a9b38b4b30ee8cb3f3d25f7527b4643a03c3dec40cd76b7b04303881ab2f731d59f0f882fb798bc6ac18ce904d1ffe93cbeb96ed1d7254d0dd26a1d0205d70114d984c2b77b",
		sig:      "56279ccd2d37e8113625732cd3f3b61b4ef9325160c7f6af7077c25049d32742607ae3f845bd66cd6752813c26067fdc23f08008cf6a531124e9ebc9264f7cfd6d6eeff15daf97dad22565ec36b69125e7b27fc93892f6ff42ce8f265dc2cf2e5758ba0d67968e800e73fd47131008f5adc863919ea0cc153cf7efff134b0bcbd0af5505ab49af7b75d63a8aa7976b8fe77baf5a699a7e38a60eb7ca64e834f3e0f89da5b6a343a01f7657fd842c091a6208503bc75de8f95de0d871a6fc114b594ff99d615825fd3b896933381452536d68d9e034f65abf3412e8e32002689e102a8bb69991e04a7ff681b62e48ee687badf8690b2ccee4bf245cd0a25dcf21",
		hashFunc: commonpb.HashType_SHA512,
		saltLen:  10,
		pubKey:   rsaPSS2048NISTKey,
	},
	{
		name:     "RSA_SSA_PSS_3072_SHA256_10",
		msg:      "886f83a22335aee35be0f76ec4c32e644c29467e1ba459fcbea2ebdf8541735829651880b207b84998d02eb529e6d5462a0648b5c1d36ce7936db11c2946946a9831696a61bc573196c0a4813e363241fb4c4a2beab999c5cb4d789262cc71891cfcfec6f6fd93809bd9df3bcc5c503e0526d5485efee77faf69caa9f77b109e",
		sig:      "92ae66dbda65a60a5f70031c3562ece74e615486acde2276c20ea01d82f7bab23af2aba27d62749850d49d2689381f1e875ade766dfe7b7f02fd601f3401dcf319caef080d73caecc08a2b4576d4cc3704bde1b7495bce086846a8a01488d00aecd54d4045f0b9e31262b460a94f0563e3d9eeb86d8f9403e5eef0d223ceb74e058a8095db8efe228d6755715bbaaafe1ab375df1112d740d951db72f6f4d25fae951a26d4c1d99f3b5a7bf311fa9cf580860b8c1b434e03d3ae0500b6457a2582275db531037a781aefc9d4f5820167a2a9cf86595fed5596246fa7fd2c8c2df0042caf9e25c59b289f58474145bf50950ecb05271afd7ce21da967b415f0de136ce5ba01fa7948bff66fea0a8063882cf88469a495ae75bba4ffb539ee5176731ec3778477f643669f94de0e4b7c856bcc511f56ad8aa23edca0c1d84d2c19abbdd191bfc0ca898fdb4b8100c44df99e5afcc93faf227a01a63c15bfd26e5e3f49fb34a98ea8a851703aad68463513d3a2ee6a4a2fe9fee958205dfd2db254",
		hashFunc: commonpb.HashType_SHA256,
		saltLen:  10,
		pubKey:   rsaPSS3072NISTKey,
	},
	{
		name:     "RSA_SSA_PSS_3072_SHA384_10",
		msg:      "5e5ca00767fad960921dcbbf16eb8e2ee85ad6db8caa6dbe2c33e17ce7607a8c6bfc6e98c6ac582679bde777ce20d3af6cb3163729c358601fceab49028d7802b131b9f10aee697503b639caf647852d3d678640ff6ec9af4906e014612f57185786eadbdcc6f497578f2b8036668bee82fe90bdb7b5a8f4d262e8a6ab4efe16",
		sig:      "2ad995df3355aafb5dc71f06f10e42ef27d5a755351806961dec23ed08dc9cf0cd8d80a40fffe5ee54bdc71f355f661b59ff7a438a642b96d3e6ef95a54e5fd7d7af188b307914b8b8d05cbc09a046545be5c53908027c7324dd84b42f2a0054768161c6b1bad21de778babfe626f74bc325fed37dbba68648ad0b70881ee765825a215c23f21ae7f4805da65ae14fa8320cfa0cc43396e7a2193317695587bd8b4a3e935607465a0d29aa44f80ffb33e95604d087362a9a297aa8585cfcb4e1781bab34fbe7ea5503fd9a1deeec50caa56d7361d1159de065d2acf667d8bd46026cbca2cf8492e4ab6be427400db381b64e220c1cca709edc2768e80db78920912a929031c9bd0e13ad9fd6560c343904dc1bad633c3cdb7563dd4cf444ef2f7d8df047fe3ded5b277f94d56abf819943303fa6d9f0b55ecc20f98e92e6f1d34761148e7a51c51d5bd012cd6032aa2b3f0646059df34045f837c7eeaca6fa16357aa2c48922e34d4fb48183d11ca049684ae198c053de473bc167531b712516",
		hashFunc: commonpb.HashType_SHA384,
		saltLen:  10,
		pubKey:   rsaPSS3072NISTKey,
	},
	{
		name:     "RSA_SSA_PSS_3072_SHA512_10",
		msg:      "be7d5fca06c75896b6bbb0333a625d876b851447bf121975bcc05527b3f6a98baaea82289a06ad66db8f6d51dc88cb9a17d42ede449c2b2bcdf09ec183b1fa158faedd1cab0de8c592edcdc8b449a99e2f1f95d0fbd2777564ce1ff6be6a8f155412992ea1a5b0bcc31cf81e2c6d9f9c9bae70a54a7ea55a69a1fd51ccea0f92",
		sig:      "04625331d8a8a03eb818e027407341feb037706e7421ae3a9c95a4119d98ee4c47c3262562ac6785c0c5fbed288478a1b69b5d51185780f4f3a3e897f453f89e279336ceaded9901d0a696ec0ced21dbca16e31b7996b642b7778e1752365f7a17c95d9e10c750c72d373deb940423fdbe63074be971590dfa9b2f6d629eae702cf715e052eb1631a934994f5bda15eaf2bf032a0059804145b50c8c68401458dd34d972d4747faa894bb830dafae440cd81096756a0897d8656c60ea7665922b0b0c21055fd411e9487e63213cc6c0ce5193fee48b99942685649de2d89f260800e8797bd4d572aa0c92b56466b431e5355c417123303a4fc908d7be8e1528724cd19906fd117a8390b8b9a61399a8284425b15025f34122f2bada19a18e3859d5dc03d6ae30aac2c7145288927aece2b2a5c2769d4de0fe90523362ab416f253a66265cb3b31613e4fb37f23319432a28838fa8adf1c3f807bbffb9d6eea78409ceb985f5d301daede0486e0fa933f81d632d3ac9690a7be4bef961c194132",
		hashFunc: commonpb.HashType_SHA512,
		saltLen:  10,
		pubKey:   rsaPSS3072NISTKey,
	},
	{
		name:     "RSA_SSA_PSS_4096_SHA256_10",
		sig:      "40a35351e11b783060d83bcafce26acf0d60e4b65c1aa487d705b9cc46393f7604c7237d168448a74c1acec7cfdedbd16c4c7bb25df9a1d89d3eb6d99e008cb61bcd466f9a30fbb4299eda0d9a327fa4102294ef08205e814bc44ba2a0243429f84a550b9d0b9dc19c823e92608a1b7e35f29d62eb11194ea55dd413ed82f35c25a1ad83f1d8844abf46b841cdbea149bd0a17bd6bd728e55d610de19618686eacab67a84fd6dc03c05deabd13bb83a26a6978d529fa15b468c35eca64c75209fb2a5cf6b624436710765e6507226b4e46686d247c17769c90e1839be25a5725262f82980bb097d7a06695d56426e244e01174dfbe9288611dfc6da3da181287c08a90488e5dc0698f9d5ec9dd0ac9dee0fe2bde7cb2f1c1aa5b61aefa44dc681f3e090b8de0e7e3eb52ca10a9c2d029aa0d8318f26e33e54d591f831a7f368db305da474fed7a7720ad3915cefd59c4c5b35d5066a48c8a9fc2e2bbb1430e7ba125c332c8d450e6d313c992878d80b4667cbfa255b9f79b82cabe2c24752c3da0917a4cbba9280279a7621724b6987e04e39f13bbd1ceec95031eb061142922160fd4c55af93148c36e36fb423ce113035d0d441aef27f7a60de29afda06425f2c51fc73c297ee8151e8a0e05b307db6f9a076271f07099cd902aff495461b7dcdd32cece0949d87e7f630f0ee5052d0e65c4496ae6645efad9e54052797388",
		msg:      "158009419260a400e8eb9d7f65c65c9c3fdc67d3d99aca0c425fbcb7fe2e7f1b0aa788eb1a35e01b2588caf12346a65f16fd1590475d5ec1d2a411526459ea1d443df706907ffdd3ca2f193f93f5a349b50357d26748b767cde6ab5cbfe76b1acb2b9eb97da5c4d2ddc8d18e3a3b1a0326d475c1c2c49ca73c0fd3fc9540cbbb",
		hashFunc: commonpb.HashType_SHA256,
		saltLen:  10,
		pubKey:   rsaPSS4096NISTKey,
	},
	{
		name:     "RSA_SSA_PSS_4096_SHA384_10",
		sig:      "a8edbfcefecfc5bd4782ec1701a99fb5c5901e07d4fd004cab64e4331c70595ed7704a5747066d19ec4f70051932d833eedd46b0d21bef7111559d4439fdc859fd538a86088fb19cff2ba3d8a1f907b0eb9ec0a6aecab645cfd05e3f8297288c015b51bc761f4a431cdeeb441155a3f465f13758018803cb724bf062213ce1f6a59b4ad5516465a2064b8920c41af8df2c2d406f776ee0ac66f19ec0ecc0874d19bc1ff5a41a0db246d66d0814c4befc7430f668e94af3a2188c7d8d44a4426ec4801d652519db2badd641382dd7ef567be5458eed7a23429ecfb3d38d96534846dc4d62bfa2106156b714fd380e6f3a31702818c3349e6d7a5aa0a452ec8645936a37767c62b03aaf7f907ce70567dbb915a8c86b1ea1c32786e5c8f160319db7641accdd53bf9d7b8f648e1082c5521c41347dc58d1455c6e72bbea93f4ecf762f980b08ef2c31567190078d7c6b772a9816bdbc1d40b5ccd0d4979b69b78e1a401bec0bb957192dd31046a2dcc2489fae00dc8fa293f89ec8b36b56acac3f87bd92e04ba6ad5df7d46d322d0cf2b930a499a35971e2a1850651a7cf7e59e930f62bba68e436836b5e47490d92e35d3dca827e4448c8c92af7d6796663ab7fabbbcef0bc9f61fc00c822e406ed8fcea1b42286ae054c40c97c1eb2656c59bd3c6b18566e32f27c0e8f5ded3afdb28f175ab90b1980667666c5d06162f975f5",
		msg:      "3874dd769d0426ee7dcbdceb67a9ad770e1781e34b15a45f656328c88ff485c1b2a083056d195afc5b20178c94f94131761cbd50a52defc8502e22cbb6f42aece9d74778d2ae4d0a76fb025a7762c856de607c7417399d463d32b14f9901e4156582f377d5ab484158c267fe1bcd880dce4b85f7ac21f700b5d79cfc3e04fd64",
		hashFunc: commonpb.HashType_SHA384,
		saltLen:  10,
		pubKey:   rsaPSS4096NISTKey,
	},
	{
		name:     "RSA_SSA_PSS_4096_SHA384_10",
		sig:      "3e6544351f1d6e4e76e354446b416544b54494831e99ac6adfdf68ca28dc8ea30cda2085d7f8ac0fec27d03c8ab0705835d647822277ec7b7bccd8c6857a9c017a6139cd88f0bf9a4559f1308445ffeafd94e010aff4127773b8ccbcaba0e8184d8ce8c990cea9d3b9f41b889bf5451eb2b6afd89b5bfe1e681e2447c4020ee93369e3bff4bfdebd03ba5b17ff78bb5dff04e4ec440d080ea26ef9aba76e9872ec271d56d678ce63588eaa50da25c005193030e0deb4b842e6aca4c645c094754a41e61263a5056852902b70dafa5381bddfa3dd6d881c5c67c33009d4fc8843c55e8662bec083ead69b1c005ea7aea175c08cf27c838aa9bb2c3eb2e08a7e458efce3f394118d069aa6e0663f7339753c49f14a1209fe8d3e546d0dad553e144939c208a48b4797afc24b9eb1788b65f568b8a815359a78bc92185f59c9532666bff497b56035a98f645d28cf12c1063f83cf736c6f38016a9626a886144cc90ad9dcae6a0d36fbd8377f13cf03342f59fbdd99f3985e17a364f0a2835332f4eb494ef16b63101f05dbc826ced2afb213da2aa368b2895fbe809a92873c6547e9755c35097c32ffc2c62ff395cec8e50a2d7ad50ed99f3daa8bfc0d16c9a63ae9fb150c88b49162d489a2cb8b0dbf260c113a9f9883728fc089e0af3026bf9a4fb3b8ef4ef85ff7f055b13b403bececb9f62bc6922153bed8b2a78b71168cea",
		msg:      "b1a82d51fc2abf919b68f369f3057136f8f2f1204337f0fb66f0a76f7c953d57047f3c68efa84213f7b3f9ac332c48cbe810cbf3a39081718412c587dd7980cafca69cc9443ebcef83ae2aab7f6d10cdd281ec34f8453ea6a76983ff5e3a678e412437bc247595eee6636fad005132055d4e3a2a6ddf8e6275feca1e29625c6a",
		hashFunc: commonpb.HashType_SHA512,
		saltLen:  10,
		pubKey:   rsaPSS4096NISTKey,
	},
}

func (t *nistRSAPSSTestVector) ProtoKey() (*rsppb.RsaSsaPssPublicKey, error) {
	e, err := hex.DecodeString(t.pubKey.e)
	if err != nil {
		return nil, fmt.Errorf("hex.DecodeString(t.pubKey.e) err = %v, want nil", err)
	}
	n, err := hex.DecodeString(t.pubKey.n)
	if err != nil {
		return nil, fmt.Errorf("hex.DecodeString(t.pubKey.n) err = %v, want nil", err)
	}
	return &rsppb.RsaSsaPssPublicKey{
		Version: 0,
		Params: &rsppb.RsaSsaPssParams{
			SigHash:    t.hashFunc,
			Mgf1Hash:   t.hashFunc,
			SaltLength: int32(t.saltLen),
		},
		E: e,
		N: n,
	}, nil
}

func TestRSASSAPSSVerifierPrimitive(t *testing.T) {
	vkm, err := registry.GetKeyManager(rsaPSSTestPublicKeyTypeURL)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", err, rsaPSSTestPublicKeyTypeURL)
	}
	for _, tc := range nistRSAPSSTestVectors {
		t.Run("nist test vector", func(t *testing.T) {
			k, err := tc.ProtoKey()
			if err != nil {
				t.Fatalf("tc.ProtoKey() err = %v, want nil", err)
			}
			sig, err := hex.DecodeString(tc.sig)
			if err != nil {
				t.Fatalf("hex.DecodeString() err = %v, want nil", err)
			}
			msg, err := hex.DecodeString(tc.msg)
			if err != nil {
				t.Fatalf("hex.DecodeString() err = %v, want nil", err)
			}
			serializedPublic, err := proto.Marshal(k)
			if err != nil {
				t.Fatalf("proto.Marshal() err = %v, want nil", err)
			}
			v, err := vkm.Primitive(serializedPublic)
			if err != nil {
				t.Fatalf("Primitive() err = %v, want nil", err)
			}
			verifier, ok := v.(tink.Verifier)
			if !ok {
				t.Fatalf("primitive isn't a tink verifier")
			}
			if err := verifier.Verify(sig, msg); err != nil {
				t.Errorf("verifier.Verify() err = %v, want nil", err)
			}
		})
	}
}

func TestRSASSAPSSVerifierPrimitiveFailsWithInvalidKey(t *testing.T) {
	type testCase struct {
		tag    string
		pubKey *rsppb.RsaSsaPssPublicKey
	}
	vkm, err := registry.GetKeyManager(rsaPSSTestPublicKeyTypeURL)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", err, rsaPSSTestPublicKeyTypeURL)
	}
	privKey, err := makeValidRSAPSSKey()
	if err != nil {
		t.Fatalf("makeValidRSAPSSKey() err = %v, want nil", err)
	}
	validPubKey := privKey.GetPublicKey()
	for _, tc := range []testCase{
		{
			tag:    "empty public key",
			pubKey: &rsppb.RsaSsaPssPublicKey{},
		},
		{
			tag: "nil params",
			pubKey: &rsppb.RsaSsaPssPublicKey{
				Version: validPubKey.GetVersion(),
				Params:  nil,
				N:       validPubKey.GetN(),
				E:       validPubKey.GetE(),
			},
		},
		{
			tag: "invalid public key version",
			pubKey: &rsppb.RsaSsaPssPublicKey{
				Version: validPubKey.GetVersion() + 1,
				Params:  validPubKey.GetParams(),
				N:       validPubKey.GetN(),
				E:       validPubKey.GetE(),
			},
		},
		{
			tag: "different sig and mgf1 hash functions",
			pubKey: &rsppb.RsaSsaPssPublicKey{
				Version: validPubKey.GetVersion(),
				Params: &rsppb.RsaSsaPssParams{
					SigHash:    commonpb.HashType_SHA256,
					Mgf1Hash:   commonpb.HashType_SHA384,
					SaltLength: validPubKey.GetParams().GetSaltLength(),
				},
				N: validPubKey.GetN(),
				E: validPubKey.GetE(),
			},
		},
		{
			tag: "negative salt length",
			pubKey: &rsppb.RsaSsaPssPublicKey{
				Version: validPubKey.GetVersion(),
				Params: &rsppb.RsaSsaPssParams{
					SigHash:    validPubKey.GetParams().GetSigHash(),
					Mgf1Hash:   validPubKey.GetParams().GetMgf1Hash(),
					SaltLength: -1,
				},
				N: validPubKey.GetN(),
				E: validPubKey.GetE(),
			},
		},
		{
			tag: "invalid hash function",
			pubKey: &rsppb.RsaSsaPssPublicKey{
				Version: validPubKey.GetVersion(),
				Params: &rsppb.RsaSsaPssParams{
					SigHash:    commonpb.HashType_UNKNOWN_HASH,
					Mgf1Hash:   commonpb.HashType_UNKNOWN_HASH,
					SaltLength: validPubKey.GetParams().GetSaltLength(),
				},
				N: validPubKey.GetN(),
				E: validPubKey.GetE(),
			},
		},
		{
			tag: "unsafe hash function",
			pubKey: &rsppb.RsaSsaPssPublicKey{
				Version: validPubKey.GetVersion(),
				Params: &rsppb.RsaSsaPssParams{
					SigHash:    commonpb.HashType_SHA1,
					Mgf1Hash:   commonpb.HashType_SHA1,
					SaltLength: validPubKey.GetParams().GetSaltLength(),
				},
				N: validPubKey.GetN(),
				E: validPubKey.GetE(),
			},
		},
		{
			tag: "invalid modulus",
			pubKey: &rsppb.RsaSsaPssPublicKey{
				Version: validPubKey.GetVersion(),
				Params:  validPubKey.GetParams(),
				N:       []byte{0x00},
				E:       validPubKey.GetE(),
			},
		},
		{
			tag: "invalid exponent",
			pubKey: &rsppb.RsaSsaPssPublicKey{
				Version: validPubKey.GetVersion(),
				Params:  validPubKey.GetParams(),
				N:       validPubKey.GetN(),
				E:       []byte{0x01},
			},
		},
		{
			tag: "exponent larger than 64 bits",
			pubKey: &rsppb.RsaSsaPssPublicKey{
				Version: validPubKey.GetVersion(),
				Params:  validPubKey.GetParams(),
				N:       validPubKey.GetN(),
				E:       random.GetRandomBytes(32),
			},
		},
	} {
		t.Run(tc.tag, func(t *testing.T) {
			serializedPubKey, err := proto.Marshal(tc.pubKey)
			if err != nil {
				t.Fatalf("proto.Marshal() err = %v, want nil", err)
			}
			if _, err := vkm.Primitive(serializedPubKey); err == nil {
				t.Errorf("Primitive() err = nil, want error")
			}
		})
	}
}
