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

package jwt_test

import (
	"bytes"
	"fmt"
	"testing"

	spb "google.golang.org/protobuf/types/known/structpb"
	"github.com/google/go-cmp/cmp"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
	"github.com/google/tink/go/jwt"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/testkeyset"
	jepb "github.com/google/tink/go/proto/jwt_ecdsa_go_proto"
	jrsppb "github.com/google/tink/go/proto/jwt_rsa_ssa_pkcs1_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

type jwkSetTestCase struct {
	tag           string
	jwkSet        string
	privateKeyset string
	publicKeyset  string
}

// synchronized with tests cases from JWK converter for C++
var jwkSetTestCases = []jwkSetTestCase{
	{
		tag: "ES256",
		jwkSet: `{
			"keys":[{
			"kty":"EC",
			"crv":"P-256",
			"x":"wO6uIxh8SkKOO8VjZXNRTteRcwCPE4_4JElKyaa0fcQ",
			"y":"7oRiYhnmkP6nqrdXWgtsWUWq5uFRLJkhyVFiWPRB278",
			"use":"sig","alg":"ES256","key_ops":["verify"],
			"kid":"EhuduQ"}]
		}`,
		privateKeyset: `{
				"primaryKeyId": 303799737,
				"key": [
				{
					"keyData": {
					"typeUrl": "type.googleapis.com/google.crypto.tink.JwtEcdsaPrivateKey",
					"value": "GiA2S/eedsXqu0DhnOlCJugsHugdpPaAGr/byxXXsZBiVRJGIiDuhGJiGeaQ/qeqt1daC2xZRarm4VEsmSHJUWJY9EHbvxogwO6uIxh8SkKOO8VjZXNRTteRcwCPE4/4JElKyaa0fcQQAQ==",
					"keyMaterialType": "ASYMMETRIC_PRIVATE"
					},
					"status": "ENABLED",
					"keyId": 303799737,
					"outputPrefixType": "TINK"
				}
			]
		}`,
	},
	{
		tag: "ES384",
		jwkSet: `{
			"keys":[{"kty":"EC","crv":"P-384",
			"x":"AEUCTkKhRDEgJ2pTiyPoSsIOERywrB2xjBDgUH8LLg0Ao9xT2SxKadxLdRFIr8Ll",
			"y":"wQcqkI9pV66PJFmJVyZ7BsqvFaqoWT-jAFvYNjsgdvAIpyB3MHWXkxNhlPYcpEIf",
			"use":"sig","alg":"ES384","key_ops":["verify"],"kid":"f-fUcw"}]
		}`,
		privateKeyset: `{
			"primaryKeyId": 2145899635,
			"key": [
				{
					"keyData": {
						"typeUrl": "type.googleapis.com/google.crypto.tink.JwtEcdsaPrivateKey",
						"value": "GjCfHcFYHsiwTcBCATSyjOyJ64iy4LGa4OuFaR9wZqkYTuYrY1I3ssxO4UK11j/IUe4SZiIwwQcqkI9pV66PJFmJVyZ7BsqvFaqoWT+jAFvYNjsgdvAIpyB3MHWXkxNhlPYcpEIfGjAARQJOQqFEMSAnalOLI+hKwg4RHLCsHbGMEOBQfwsuDQCj3FPZLEpp3Et1EUivwuUQAg==",
						"keyMaterialType": "ASYMMETRIC_PRIVATE"
					},
					"status": "ENABLED",
					"keyId": 2145899635,
					"outputPrefixType": "TINK"
				}
			]
		}`,
	},
	{
		tag: "ES512",
		jwkSet: `{
			"keys":[{"kty":"EC","crv":"P-521",
			"x":"AKRFrHHoTaFAO-d4sCOw78KyUlZijBgqfp2rXtkLZ_QQGLtDM2nScAilkryvw3c_4fM39CEygtSunFLI9xyUyE3m",
			"y":"ANZK5JjTcNAKtezmXFvDSkrxdxPiuX2uPq6oR3M0pb2wqnfDL-nWeWcKb2nAOxYSyydsrZ98bxBL60lEr20x1Gc_",
			"use":"sig","alg":"ES512","key_ops":["verify"],"kid":"WDqzeQ"}]
		}`,
		privateKeyset: `{
			"primaryKeyId": 1480242041,
			"key": [
				{
					"keyData": {
						"typeUrl": "type.googleapis.com/google.crypto.tink.JwtEcdsaPrivateKey",
						"value": "GkIBnhWq6UrOj8hKwGovjSsLT+dtAGlRqoIkQ2FzMeKxIApx0dT3O4yHrmi6v5sElZHM6BsLz47IopAOajVRYGh48b0SigEiQgDWSuSY03DQCrXs5lxbw0pK8XcT4rl9rj6uqEdzNKW9sKp3wy/p1nlnCm9pwDsWEssnbK2ffG8QS+tJRK9tMdRnPxpCAKRFrHHoTaFAO+d4sCOw78KyUlZijBgqfp2rXtkLZ/QQGLtDM2nScAilkryvw3c/4fM39CEygtSunFLI9xyUyE3mEAM=",
						"keyMaterialType": "ASYMMETRIC_PRIVATE"
					},
					"status": "ENABLED",
					"keyId": 1480242041,
					"outputPrefixType": "TINK"
				}
			]
		}`,
	},
	{
		tag: "ES256_NO_KID",
		jwkSet: `{
			"keys":[{
			"kty":"EC",
			"crv":"P-256",
			"x":"ytH8MlvqTx3X-eL0pdx4ULKUb2YOi2DPnIPpSaIk28M",
			"y":"AO5TMe5lNcjJpuGjjGtHd4gX9POG9dh_vG-8ptp7HJs",
			"use":"sig","alg":"ES256","key_ops":["verify"]}]
		}`,
		privateKeyset: `{
			"primaryKeyId": 765975903,
			"key": [
				{
					"keyData": {
						"typeUrl": "type.googleapis.com/google.crypto.tink.JwtEcdsaPrivateKey",
						"value": "GiCbUAItoAVleOSwYdPWs563CCFhGHSdX4t/C2xBY2J/ERJGIiAA7lMx7mU1yMmm4aOMa0d3iBf084b12H+8b7ym2nscmxogytH8MlvqTx3X+eL0pdx4ULKUb2YOi2DPnIPpSaIk28MQAQ==",
						"keyMaterialType": "ASYMMETRIC_PRIVATE"
					},
					"status": "ENABLED",
					"keyId": 765975903,
					"outputPrefixType": "RAW"
				}
			]
		}`,
	},
	{
		tag: "multiple keys",
		jwkSet: `{
			"keys":[
				{
					"kty":"EC",
					"crv":"P-256",
					"x":"wO6uIxh8SkKOO8VjZXNRTteRcwCPE4_4JElKyaa0fcQ",
					"y":"7oRiYhnmkP6nqrdXWgtsWUWq5uFRLJkhyVFiWPRB278",
					"use":"sig","alg":"ES256","key_ops":["verify"],
					"kid":"EhuduQ"
				},
				{
					"kty":"EC",
					"crv":"P-384",
					"x":"AEUCTkKhRDEgJ2pTiyPoSsIOERywrB2xjBDgUH8LLg0Ao9xT2SxKadxLdRFIr8Ll",
					"y":"wQcqkI9pV66PJFmJVyZ7BsqvFaqoWT-jAFvYNjsgdvAIpyB3MHWXkxNhlPYcpEIf",
					"use":"sig","alg":"ES384","key_ops":["verify"],
					"kid":"f-fUcw"
				}
			]
		}`,
		privateKeyset: `{
				"primaryKeyId": 303799737,
				"key": [
				{
					"keyData": {
					"typeUrl": "type.googleapis.com/google.crypto.tink.JwtEcdsaPrivateKey",
					"value": "GiA2S/eedsXqu0DhnOlCJugsHugdpPaAGr/byxXXsZBiVRJGIiDuhGJiGeaQ/qeqt1daC2xZRarm4VEsmSHJUWJY9EHbvxogwO6uIxh8SkKOO8VjZXNRTteRcwCPE4/4JElKyaa0fcQQAQ==",
					"keyMaterialType": "ASYMMETRIC_PRIVATE"
					},
					"status": "ENABLED",
					"keyId": 303799737,
					"outputPrefixType": "TINK"
				},
				{
					"keyData": {
						"typeUrl": "type.googleapis.com/google.crypto.tink.JwtEcdsaPrivateKey",
						"value": "GjCfHcFYHsiwTcBCATSyjOyJ64iy4LGa4OuFaR9wZqkYTuYrY1I3ssxO4UK11j/IUe4SZiIwwQcqkI9pV66PJFmJVyZ7BsqvFaqoWT+jAFvYNjsgdvAIpyB3MHWXkxNhlPYcpEIfGjAARQJOQqFEMSAnalOLI+hKwg4RHLCsHbGMEOBQfwsuDQCj3FPZLEpp3Et1EUivwuUQAg==",
						"keyMaterialType": "ASYMMETRIC_PRIVATE"
					},
					"status": "ENABLED",
					"keyId": 2145899635,
					"outputPrefixType": "TINK"
				}
			]
		}`,
	},
	{
		tag: "RS256",
		jwkSet: `{
			"keys":[{
				"kty":"RSA",
				"n": "vmUOa62TYrxj7N8rZVAzoEdSnmsRQaNWBMAdB8adGa8n4ycGiYWoGv0uZWc8vH2jn6l3Pa_72bb2IHf3-KD2UaTwLk1x3yShXybEoS5ZF9bemzrn2ohNixGoN7Ofj7wPb61Z-F1Nv53nq308z-RI1WeyIH-9HjuIcuUxaWY0VevsXzCehMJP5g7kVzyl55bYcRi28didkVazrzVgNG35yNNMEL32oW1Vfvvp7hfQHtxSwkFOPzJgzIPHbJFbxALGrrgXHsoq7UtDQdS9vvoEp4_JzQhCtnCEKahgkTwOWyT96OlRGYiPJSFHWTujy1Qnd6OKc8LGEspAX4oD6Zl-YQ",
				"e":"AQAB",
				"use":"sig",
				"alg":"RS256",
				"key_ops":["verify"],
				"kid":"TCGiGw"
			}]
		}`,
		privateKeyset: `{
			"primaryKeyId":1277272603,
			"key":[{
				"keyData":{
					"typeUrl":
							"type.googleapis.com/google.crypto.tink.JwtRsaSsaPkcs1PrivateKey",
					"value":"QoABP3S5U0JiFQcqcMFT0Ysqk7FK2NunBCY9o+EAE+svaQi6zWQq2ODFoxB2NU9nqa3ZbhRiCdKNLz6o+jOTIpemKx8Gh/7GufRGLFAjjMchZYs3ripiTNSMaqXgm6ECt8DqrAZbMQ7D3Ha1vArcZG97pbE9t3m4M87zhLs3wPYd/kQ6gAEFPE2GLD5ai8VYd/Q0ePZR0ttLgkJ/2yIig5T8YyJaoZEPjK+v3zVFQuGguJApnl2tC0S7OqOtqsDZ5Dux0H3Cx85FLeyB2STHlXtq9GUGI2VrC/TP3OASc6ap75WMKZRpowEVaip8wWehAOL+VIgTajiFf0yXdSodc4ZjJKreiTKAAd6ahHQiVJapNKY6XANgA+JmluAWq/Fk1LmEnTybWVelcODbppwIvhJ6Xuz6kjuEhhxsUtkPO4vuZJfEF8DWAH5L/FHjJpgP3NnDoNVzGOL5w8SdgIfgCS0UqBLSv2/KhlIEijuL9NYaqydN1cPcjdeadSMcDSIwKjNASRVaPZDJKoABx1/CfOqCbE8eh450YvGwYvII+ro8tR+uusnt2QuQZux3wvl9eto9Dr+5Iq/0bKqpMMgvYHIT+mlkgK6SYLcynZx+SYMAtbixa0nH1lJnnBodOJS6zdMRTcFkpI4g/CbCvzTp5gF5EkfBSbVToVLqICydokKnTvNK6chX3MEUjskigAH0eGwQwn174yJzJTUWH4cRxDredI6LkjADm/ikza76AHT8qRJHJkmwSXL88p3M2bYFN+g9Z/FTL21Ylc0mxn/iII3vabfZWZTWK9QGR7YjAicFyLDeu/ZccCkCXgTFzqqlZ7w4Sv05hWz57xxm81JyxftzapeflfAmjRircFXG2RqAAgub/Z28+SFSf6zSPFMKiYVWx//DI0ubbiuuu65tUse9xYq9JtHEobgYk0dJXNuY9RzPkGblZ8/SD06yRf9l8DMRAbivDfgXY5QZ2PBDk1jn6A2y0S+i80h9MILJ+/sfkljiyvtBFDQwiI9tPOOnxbWmg6bl5xYUdvjbhxBoVB1fgOtAid6gGuLstbf8ycV+DkaWg3mo4054ge9BBT4eWKGC/LHctSaQ/OBs5cbGW+UqZxIjSN9YeOTkbvNKO4l4jGTg0BUBPB3GH8KQPtE4sbBhUDyjYYgAZZcSaRq7AfhLUkiDSfIVcKAIoEOaTS63vf2BQlbW8/HuNlWNUX0M+hkSigIiAwEAARqAAr5lDmutk2K8Y+zfK2VQM6BHUp5rEUGjVgTAHQfGnRmvJ+MnBomFqBr9LmVnPLx9o5+pdz2v+9m29iB39/ig9lGk8C5Ncd8koV8mxKEuWRfW3ps659qITYsRqDezn4+8D2+tWfhdTb+d56t9PM/kSNVnsiB/vR47iHLlMWlmNFXr7F8wnoTCT+YO5Fc8peeW2HEYtvHYnZFWs681YDRt+cjTTBC99qFtVX776e4X0B7cUsJBTj8yYMyDx2yRW8QCxq64Fx7KKu1LQ0HUvb76BKePyc0IQrZwhCmoYJE8Dlsk/ejpURmIjyUhR1k7o8tUJ3ejinPCxhLKQF+KA+mZfmEQAQ==",
					"keyMaterialType":"ASYMMETRIC_PRIVATE"
				},
				"status":"ENABLED",
				"keyId":1277272603,
				"outputPrefixType":"TINK"
			}]
		}`,
	},
	{
		tag: "RS384",
		jwkSet: `{
			"keys":[{
				"kty":"RSA",
				"n":"AI83_8Uy0v4xS6kDZKqcqzSbeyksy2C67ajtI41J2KMDtO9jUaEAQ9uDhMubjZzPYh1wf_gtJgAC5PSiI3fOLUG0AHCbi_yXVfH3_1U_Yl4b_e8yx_NPyuIvwHwXwE5a32hiss9PuY2-qEivH5LK4AXxPiTiUc9x4gh1OwZaSTYWT7SRO-0ROwYwCwpg4Uf0IMLtmHou_NmNw0uOlOgKfx-EFmMzV-5pspEnwsHq_ijFSxmHNAdy5S0n4u1LIKKmgXJIyUu3AKfAJMydn6nTKzrOcpX0yMnxPq9yP8xKuK_mXysFyNvmS0Sq5c-grOETFeMFScweoUpWVnYOCCSyZ93yAhsTUWnDjZd7iuji9Y7zUo4PWlKXyRRz_aSpxrsn70LOZNLLUjILVeyfCRs2JXptfxCNg3wg6FVAH0xTORmPGICgWDmwOFgP1Y6tW-p0cnK8LwVkuRclyKAMvTtYm9xZZHUSjw86rHEnB2VfsPTIn0_WAVnJ2OAKhuVMtwjB7Q",
				"e":"AQAB",
				"use":"sig",
				"alg":"RS384",
				"key_ops":["verify"],
				"kid":"FVLRIg"
			}]
		}`,
		privateKeyset: `{
			"primaryKeyId":357749026,
			"key":[{
				"keyData":{
					"typeUrl":
							"type.googleapis.com/google.crypto.tink.JwtRsaSsaPkcs1PrivateKey",
					"value":"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",
					"keyMaterialType":"ASYMMETRIC_PRIVATE"
				},
				"status":"ENABLED",
				"keyId":357749026,
				"outputPrefixType":"TINK"
			}]
		}`,
	},
	{
		tag: "RS512",
		jwkSet: `{
			"keys":[{
				"kty":"RSA",
				"n":"AKZtuHAGYy-1Mc78sdp1gOV3jMCJtO7NmhyLSproWcBnqSN1g9mB2EdB22-WLWhB_U_JlZRCdHT6CxPHSid0c9JJc-2CmiV9zU2sVTJUkCytOVS0hrcPEz5JK6a6VVy-Skc_1-I0D2YurXd0aRByDALC8heHMok6VQXW8qwHgRyc0Jr1RcbY-CF_SMlRXn88g4e3bnk1AJiPcmHsJOcwkanwlWxq46DxPv5ff0ruXN4gPDYU-6_J6yZJreYjwrl-LhkqzOkz6e-LE4sdI5WFJQR9cGGRMf4ktgF3kqFtcFNFkGtdOvw5MdLe0eaENDzZ8TZyQDgiHYl878x8uPPpmoeif5af_ZUAsrv_bV-h3RpSoTdTP4SlQMmP-3y2R2LxvUs_CiUahoVFwTt_bRHO0Qy-QwpTvAdJX8CzrK2auqycFawYm8xYjj_epTFSwBCJuZjamxpZSa29zTDqP4AXwt2-9LO-70j5muzDQL35czpBgaXSAEJkrM9du91OjkJ2vtYFVLjWougN5uVpEBx1Isk_KgreOgl3lF1vs2EjTuihaxJhM-17alJLmDL06ZEDsht2Uhu_ZExEfPwTKaR_-kfjlamuoLUvTtVhzNZuOHD_XAOrGafMjM9WVq_D5XjqF7WFnb_t4YIOQNmGeOeIFLb4LlR5nHB1HIHUpAWazrvl",
				"e":"AQAB",
				"use":"sig",
				"alg":"RS512",
				"key_ops":["verify"],
				"kid":"fVf-Qw"
			}]
		}`,
		privateKeyset: `{
			"primaryKeyId":2102918723,
			"key":[{
				"keyData":{
					"typeUrl":
							"type.googleapis.com/google.crypto.tink.JwtRsaSsaPkcs1PrivateKey",
					"value":"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",
					"keyMaterialType":"ASYMMETRIC_PRIVATE"
				},
				"status":"ENABLED",
				"keyId":2102918723,
				"outputPrefixType":"TINK"
			}]
		}`,
	},
	{
		tag: "RS256_NO_KID",
		jwkSet: `{
			"keys":[{
				"kty":"RSA",
				"n":"AImrUP3PDttint7alBxKexY-Oe4nCj0TOZ06yuKgq7UQu-3Gc8KJyQHO5SzPlMBy6FjcWqOzz-kkNm9sej3AsdGhTJCcOCYDoLgArYCaMQoMLOOjMQJTVbHeiPpyVgHzvpG9Xw_IVNPbRJhsT4mzqHuyopUEEexVQcFo6F3U8zE1kppxzoMvIiz5-Zm6dFX8EozolMD2TLDh4NZFAb-6uJs8TYzS8Od6V0BVh1CfHL1CuIpvIirkgki2RGXNE1r57bhJfMZUWtqAUXb5SM2IFhLUcgGLV-PfxP2cxcJ7HHhk5-lFf5794CmqcFa4mliR2tJRnhUR2vmlgxqUjzwK3HE",
				"e":"AQAB",
				"use":"sig",
				"alg":"RS256",
				"key_ops":["verify"]
			}]
		}`,
		privateKeyset: `{
			"primaryKeyId":234505441,
			"key":[{
				"keyData":{
					"typeUrl":
							"type.googleapis.com/google.crypto.tink.JwtRsaSsaPkcs1PrivateKey",
					"value":"EosCEAEagQIAiatQ/c8O22Ke3tqUHEp7Fj457icKPRM5nTrK4qCrtRC77cZzwonJAc7lLM+UwHLoWNxao7PP6SQ2b2x6PcCx0aFMkJw4JgOguACtgJoxCgws46MxAlNVsd6I+nJWAfO+kb1fD8hU09tEmGxPibOoe7KilQQR7FVBwWjoXdTzMTWSmnHOgy8iLPn5mbp0VfwSjOiUwPZMsOHg1kUBv7q4mzxNjNLw53pXQFWHUJ8cvUK4im8iKuSCSLZEZc0TWvntuEl8xlRa2oBRdvlIzYgWEtRyAYtX49/E/ZzFwnsceGTn6UV/nv3gKapwVriaWJHa0lGeFRHa+aWDGpSPPArccSIDAQABGoACOgE5vcbpLpxt7d3Qu97R37xWMja2xKb+BnZIF5a04jRryjJsgdIGJEHlI61Osot3xEEL25+egU/ls6rUEoLHKVk55lA8BCBRLlXyxJWzBdW9cChJNP6hw7DMrCFShb4KVGOi0waIXz8qtsIj/RP6cCwC/qBZYOdHLlOiXC6mTNv0blQ2Cb9yfZZ1Lz855DH0l2/GMdZYXwb6JElM+u/vR7lxTp4Wc6kq/31PULDH7G+Ps+QpXxHMIqghgSWyRsJ9+SHv5yo7JxA58eTQEUXkI6RCJJQ3pSXjdveBzzPyN6ZCmjz91Np3oPh36dZtknW0UspZ6Jnpc5GLphkvG8GblSKBAQC/vcua6r6FGW0VO2yD93nWgX1qepmULYGw7lv+mfOvodPUr+8EqDZXaRzUqCHynhVfb1BDEsoxP9aLoPVFZoJbL1MqBnUx6X0FXoKu2FzqsEJYw2qnl4VLhFn7xebnR+vwv+MMYf+yvnIdcMfmrZhWmCS4hTFQlJDfxji2SPSdByqBAQC3znfJnB2xC7eDUCTSH49h/xW1YWaS6nTqXvk3LJeq4tX2WGBWxfCLh6xpNpzF31xCDdYlt+yGcy6UUBKr4TteePrWf6jY9TWJZO7FvAqIIIxaQv3a/0A4/sgzYcrr2ansWzhNtfCESxOaPFVfLE1wh/PpJBzbcltRbG/mEY3UxzKBAQCfvXhN5Pm6m1c0lCAwxVE88v5QYjlmqI7en4YG062gCbsX+0au45D6O7joNfaqUSdPLcZ5SsMmSp/sDbmpCuDZJNEtNtoWLgaZHYbUMa8fWp67onpNiz9ija4Fwnc/Ab1AAi0fGNnUyTL68gWoWcGLiw80pspR7qPPui1vN9KKqzqAASl2qg8Q6KHHwt4cdjHwbKfuozcHgdwih71XL2EC7jPed+XaieEJRfoz4PDbIQKCII3GEUjw9Kpf0WIjrhKX/IyTPgKlSbGnnywfWL3CbZ3HueGiuyFr81DoKMFujhgmQe7PpSPipx8w0Hs6oQeXNuDryloNi3T1lyQHEjcUPqqBQoABcIm6r6QyTlBactKBKEqyhkXF1tCvw7YR9herJoubM/xklWzU5J8bgSQ1h4dutlANutXFqeOInUufyPChP3inQhcirp3CccJFaMP9uevRMMhUxyOyQkpOfxnAe7hvCjRsDDZZqh5bi5siNzeIEnU1s7sq/0XvzZA7G5fGZgb+dZs=",
					"keyMaterialType":"ASYMMETRIC_PRIVATE"
				},
				"status":"ENABLED",
				"keyId":234505441,
				"outputPrefixType":"RAW"
			}]
		}`,
	},
}

func TestToPublicKeysetHandle(t *testing.T) {
	for _, tc := range jwkSetTestCases {
		t.Run(tc.tag, func(t *testing.T) {
			ks, err := jwt.JWKSetToPublicKeysetHandle([]byte(tc.jwkSet))
			if err != nil {
				t.Errorf("jwt.JWKSetToPublicKeysetHandle() err = %v, want nil", err)
			}
			jwkSet, err := jwt.JWKSetFromPublicKeysetHandle(ks)
			if err != nil {
				t.Errorf("jwt.JWKSetFromPublicKeysetHandle() err = %v, want nil", err)
			}
			want := &spb.Struct{}
			if err := want.UnmarshalJSON([]byte(tc.jwkSet)); err != nil {
				t.Errorf("want.UnmarshalJSON() err = %v, want nil", err)
			}
			got := &spb.Struct{}
			if err := got.UnmarshalJSON(jwkSet); err != nil {
				t.Errorf("got.UnmarshalJSON() err = %v, want nil", err)
			}
			if !cmp.Equal(want, got, protocmp.Transform()) {
				t.Errorf("mismatch in jwk sets: diff (-want,+got): %v", cmp.Diff(want, got, protocmp.Transform()))
			}
		})
	}
}

func createKeysetHandle(key string) (*keyset.Handle, error) {
	ks, err := keyset.NewJSONReader(bytes.NewReader([]byte(key))).Read()
	if err != nil {
		return nil, fmt.Errorf("keyset.NewJSONReader().Read() err = %v, want nil", err)
	}
	return testkeyset.NewHandle(ks)
}

func TestJWKSetToPublicKeysetHandleVerifyValidJWT(t *testing.T) {
	rawJWT, err := jwt.NewRawJWT(&jwt.RawJWTOptions{WithoutExpiration: true})
	if err != nil {
		t.Fatalf("jwt.NewRawJWT() err = %v, want nil", err)
	}
	validator, err := jwt.NewValidator(&jwt.ValidatorOpts{AllowMissingExpiration: true})
	if err != nil {
		t.Fatalf("jwt.NewValidator() err = %v, want nil", err)
	}
	for _, tc := range jwkSetTestCases {
		t.Run(tc.tag, func(t *testing.T) {
			privateHandle, err := createKeysetHandle(tc.privateKeyset)
			if err != nil {
				t.Fatalf("createKeysetHandle() err = %v, want nil", err)
			}
			signer, err := jwt.NewSigner(privateHandle)
			if err != nil {
				t.Fatalf("jwt.NewSigner() err = %v, want nil", err)
			}
			compact, err := signer.SignAndEncode(rawJWT)
			if err != nil {
				t.Fatalf("signer.SignAndEncode() err = %v, want nil", err)
			}
			pubHandle, err := jwt.JWKSetToPublicKeysetHandle([]byte(tc.jwkSet))
			if err != nil {
				t.Fatalf("jwt.JWKSetToPublicKeysetHandle() err = %v, want nil", err)
			}
			verifier, err := jwt.NewVerifier(pubHandle)
			if err != nil {
				t.Fatalf("jwt.NewVerifier() err = %v, want nil", err)
			}
			if _, err := verifier.VerifyAndDecode(compact, validator); err != nil {
				t.Errorf("verifier.VerifyAndDecode() err = %v, want nil", err)
			}
		})
	}
}

func TestJWKSetToPublicKeysetHandleInvalidJSONFails(t *testing.T) {
	if _, err := jwt.JWKSetToPublicKeysetHandle([]byte(`({[}])`)); err == nil {
		t.Errorf("jwt.JWKSetToPublicKeysetHandle() err = nil, want error")
	}
}

func TestJWKSetToPublicKeysetPrimitiveRS256SmallModulusFails(t *testing.T) {
	jwk := `{"keys":[
		{"kty":"RSA",
		 "n":"AQAB",
		 "e":"AQAB",
		 "use":"sig",
		 "alg":"RS256",
		 "key_ops":["verify"],
		 "kid":"DfpE4Q"
		}]
	}`
	// Keys in the keyset are validated when the primitive is generated.
	// JWKSetToPublicKeysetHandle but NewVerifier will fail.
	pubHandle, err := jwt.JWKSetToPublicKeysetHandle([]byte(jwk))
	if err != nil {
		t.Fatalf("jwt.JWKSetToPublicKeysetHandle() err = %v, want nil", err)
	}
	if _, err := jwt.NewVerifier(pubHandle); err == nil {
		t.Errorf("jwt.NewVerifier() err = nil, want error")
	}
}

func TestJWKSetToPublicKeysetRS256CorrectlySetsKID(t *testing.T) {
	jwkSet := `{"keys":[
      {"kty":"RSA",
       "n":"AQAB",
       "e":"AQAB",
       "use":"sig",
       "alg":"RS256",
       "key_ops":["verify"],
       "kid":"DfpE4Q"
      }]}`
	kh, err := jwt.JWKSetToPublicKeysetHandle([]byte(jwkSet))
	if err != nil {
		t.Fatalf("JWKSetToPublicKeysetHandle() err = %v, want nil", err)
	}
	ks := testkeyset.KeysetMaterial(kh)
	key := ks.GetKey()[0]
	if key.GetOutputPrefixType() != tinkpb.OutputPrefixType_RAW {
		t.Errorf("key.GetOutputPrefixType() got %q, want %q", key.GetOutputPrefixType(), tinkpb.OutputPrefixType_RAW)
	}
	if key.GetKeyData() == nil {
		t.Fatalf("GetKeyData() got nil, want *tinkpb.KeyData")
	}
	pubKey := &jrsppb.JwtRsaSsaPkcs1PublicKey{}
	if err := proto.Unmarshal(key.GetKeyData().GetValue(), pubKey); err != nil {
		t.Fatalf("proto.Unmarshal() err = %v, want nil", err)
	}
	if pubKey.GetCustomKid().GetValue() != "DfpE4Q" {
		t.Errorf("pubKey.GetCustomKid().GetValue() = %q, want %q", pubKey.GetCustomKid().GetValue(), "DfpE4Q")
	}
}

func TestJWKSetToPublicKeysetRS256WithoutOptionalFieldsSucceeds(t *testing.T) {
	jwkSet := `{"keys":[
      {"kty":"RSA",
       "n":"AQAB",
       "e":"AQAB",
       "alg":"RS256"
      }]}`
	if _, err := jwt.JWKSetToPublicKeysetHandle([]byte(jwkSet)); err != nil {
		t.Fatalf("jwt.JWKSetToPublicKeysetHandle() err = %v, want nil", err)
	}
}

func TestJWKSetToPublicKeysetInvalidRS256JWKSet(t *testing.T) {
	for _, tc := range []jwkSetTestCase{
		{
			tag: "RS256 without kty",
			jwkSet: `{"keys":[
				{"n":"AQAB",
				 "e":"AQAB",
				 "use":"sig",
				 "alg":"RS256",
				 "key_ops":["verify"],
				 "kid":"DfpE4Q"
				}]
			}`,
		},
		{
			tag: "RS256 without alg",
			jwkSet: `{"keys":[
				{"kty":"RSA",
				 "n":"AQAB",
				 "e":"AQAB",
				 "use":"sig",
				 "key_ops":["verify"],
				 "kid":"DfpE4Q"
				}]
			}`,
		},
		{
			tag: "RS256 invalid kty",
			jwkSet: `{"keys":[
				{"kty":"EC",
				 "n":"AQAB",
				 "e":"AQAB",
				 "use":"sig",
				 "alg":"RS256",
				 "key_ops":["verify"],
				 "kid":"DfpE4Q"
				}]
			}`,
		},
		{
			tag: "RS256 invalid key ops",
			jwkSet: `{"keys":[
				{"kty":"RSA",
				 "n":"AQAB",
				 "e":"AQAB",
				 "use":"sig",
				 "alg":"RS256",
				 "key_ops":["verify "],
				 "kid":"DfpE4Q"
				}]
			}`,
		},
		{
			tag: "RS invalid alg",
			jwkSet: `{"keys":[
				{"kty":"RSA",
				 "n":"AQAB",
				 "e":"AQAB",
				 "use":"sig",
				 "alg":"RS257",
				 "key_ops":["verify"],
				 "kid":"DfpE4Q"
				}]
			}`,
		},
		{
			tag: "RS256 invalid key ops type",
			jwkSet: `{"keys":[
				{"kty":"RSA",
				 "n":"AQAB",
				 "e":"AQAB",
				 "use":"sig",
				 "alg":"RS256",
				 "key_ops":"verify",
				 "kid":"DfpE4Q"
				}]
			}`,
		},
		{
			tag: "RS256 invalid use",
			jwkSet: `{"keys":[
				{"kty":"RSA",
				 "n":"AQAB",
				 "e":"AQAB",
				 "use":"zag",
				 "alg":"RS256",
				 "key_ops":["verify"],
				 "kid":"DfpE4Q"
				}]
			}	`,
		},
		{
			tag: "RS256 without modulus",
			jwkSet: `{"keys":[
				{"kty":"RSA",
				 "e":"AQAB",
				 "use":"sig",
				 "alg":"RS256",
				 "key_ops":["verify"],
				 "kid":"DfpE4Q"
				}]
			}`,
		},
		{
			tag: "RSS256 without exponent",
			jwkSet: `{"keys":[
				{"kty":"RSA",
				 "n":"AQAB",
				 "use":"sig",
				 "alg":"RS256",
				 "key_ops":["verify"],
				 "kid":"DfpE4Q"
				}]
			}`,
		},
	} {
		t.Run(tc.tag, func(t *testing.T) {
			if _, err := jwt.JWKSetToPublicKeysetHandle([]byte(tc.jwkSet)); err == nil {
				t.Fatalf("jwt.JWKSetToPublicKeysetHandle() err = nil, want error")
			}
		})
	}
}

func TestJWKSetToPublicKeysetES256WithSmallXPrimitiveFails(t *testing.T) {
	jwk := `{
    "keys":[{
    "kty":"EC",
    "crv":"P-256",
    "x":"wO6uIxh8Sk",
    "y":"7oRiYhnmkP6nqrdXWgtsWUWq5uFRLJkhyVFiWPRB278",
    "use":"sig","alg":"ES256","key_ops":["verify"]}],
    "kid":"EhuduQ"
  }`
	// Keys in the keyset are validated when the primitive is generated.
	// JWKSetToPublicKeysetHandle but NewVerifier will fail.
	pubHandle, err := jwt.JWKSetToPublicKeysetHandle([]byte(jwk))
	if err != nil {
		t.Fatalf("jwt.JWKSetToPublicKeysetHandle() err = %v, want nil", err)
	}
	if _, err := jwt.NewVerifier(pubHandle); err == nil {
		t.Errorf("jwt.NewVerifier() err = nil, want error")
	}
}

func TestJWKSetToPublicKeysetES256WithSmallYFails(t *testing.T) {
	jwk := `{
    "keys":[{
    "kty":"EC",
    "crv":"P-256",
    "x":"wO6uIxh8SkKOO8VjZXNRTteRcwCPE4_4JElKyaa0fcQ",
    "y":"7oRiYhnmkP6nqrdXWgtsWUWq5uFRLJkhyVFiWPRB27",
    "use":"sig","alg":"ES256","key_ops":["verify"]}],
    "kid":"EhuduQ"
  }`
	// Keys in the keyset are validated when the primitive is generated.
	// JWKSetToPublicKeysetHandle but NewVerifier will fail.
	pubHandle, err := jwt.JWKSetToPublicKeysetHandle([]byte(jwk))
	if err != nil {
		t.Fatalf("jwt.JWKSetToPublicKeysetHandle() err = %v, want nil", err)
	}
	if _, err := jwt.NewVerifier(pubHandle); err == nil {
		t.Errorf("jwt.NewVerifier() err = nil, want error")
	}
}

func TestJWKSetToPublicKeysetES256CorrectlySetsKID(t *testing.T) {
	jwk := `{
    "keys":[{
    "kty":"EC",
    "crv":"P-256",
    "x":"wO6uIxh8SkKOO8VjZXNRTteRcwCPE4_4JElKyaa0fcQ",
    "y":"7oRiYhnmkP6nqrdXWgtsWUWq5uFRLJkhyVFiWPRB278",
    "use":"sig","alg":"ES256","key_ops":["verify"],
    "kid":"EhuduQ"}]
  }`
	pubHandle, err := jwt.JWKSetToPublicKeysetHandle([]byte(jwk))
	if err != nil {
		t.Fatalf("jwt.JWKSetToPublicKeysetHandle() err = %v, want nil", err)
	}
	ks := testkeyset.KeysetMaterial(pubHandle)

	if len(ks.GetKey()) != 1 {
		t.Errorf("len(ks.GetKey()) got %d keys, want 1", len(ks.GetKey()))
	}
	key := ks.GetKey()[0]
	if key.GetOutputPrefixType() != tinkpb.OutputPrefixType_RAW {
		t.Errorf("key.GetOutputPrefixType() got %q, want %q", key.GetOutputPrefixType(), tinkpb.OutputPrefixType_RAW)
	}
	if key.GetKeyData() == nil {
		t.Fatalf("invalid key")
	}
	pubKey := &jepb.JwtEcdsaPublicKey{}
	if err := proto.Unmarshal(key.GetKeyData().GetValue(), pubKey); err != nil {
		t.Fatalf("proto.Unmarshal(key.GetKeyData(), pubKey) err = %v, want nil", err)
	}
	if pubKey.GetCustomKid().GetValue() != "EhuduQ" {
		t.Errorf("key.GetCustomKid() got %q, want EhuduQ", pubKey.GetCustomKid())
	}
}

func TestJWKSetToPublicKeysetES256WithoutOptionalFieldsSucceeds(t *testing.T) {
	jwk := `{
    "keys":[{
    "kty":"EC",
    "crv":"P-256",
    "x":"wO6uIxh8SkKOO8VjZXNRTteRcwCPE4_4JElKyaa0fcQ",
    "y":"7oRiYhnmkP6nqrdXWgtsWUWq5uFRLJkhyVFiWPRB278",
    "alg":"ES256"}]
  }`
	if _, err := jwt.JWKSetToPublicKeysetHandle([]byte(jwk)); err != nil {
		t.Fatalf("jwt.JWKSetToPublicKeysetHandle() err = %v, want nil", err)
	}
}

func TestJWKSetToPublicKeysetInvalidES256PublicKeys(t *testing.T) {
	for _, tc := range []jwkSetTestCase{
		{
			tag:    "jwk set is not a json",
			jwkSet: `5`,
		},
		{
			tag:    "empty jwk set",
			jwkSet: `{}`,
		},
		{
			tag:    "no keys in jwk set",
			jwkSet: `{"keys": []}`,
		},
		{
			tag:    "keys of wrong type in jwk set",
			jwkSet: `{"keys": "value"}`,
		},
		{
			tag:    "keys not a json object",
			jwkSet: `{"keys":[1]}`,
		},
		{
			tag: "without kty",
			jwkSet: `{
				"keys":[{
				"crv":"P-256",
				"x":"wO6uIxh8SkKOO8VjZXNRTteRcwCPE4_4JElKyaa0fcQ",
				"y":"7oRiYhnmkP6nqrdXWgtsWUWq5uFRLJkhyVFiWPRB278",
				"use":"sig","alg":"ES256","key_ops":["verify"],
				"kid":"EhuduQ"}]
			}`,
		},
		{
			tag: "without algorithm",
			jwkSet: `{
				"keys":[{
				"kty":"EC",
				"crv":"P-256",
				"x":"wO6uIxh8SkKOO8VjZXNRTteRcwCPE4_4JElKyaa0fcQ",
				"y":"7oRiYhnmkP6nqrdXWgtsWUWq5uFRLJkhyVFiWPRB278",
				"use":"sig","key_ops":["verify"],
				"kid":"EhuduQ"}]
			}`,
		},
		{
			tag: "empty algorithm",
			jwkSet: `{
				"keys":[{
				"kty":"EC",
				"crv":"P-256",
				"x":"wO6uIxh8SkKOO8VjZXNRTteRcwCPE4_4JElKyaa0fcQ",
				"y":"7oRiYhnmkP6nqrdXWgtsWUWq5uFRLJkhyVFiWPRB278",
				"use":"sig", "alg":"", "key_ops":["verify"],
				"kid":"EhuduQ"}]
			}`,
		},
		{
			tag: "invalid algorthm prefix",
			jwkSet: `{
				"keys":[{
				"kty":"EC",
				"crv":"P-256",
				"x":"wO6uIxh8SkKOO8VjZXNRTteRcwCPE4_4JElKyaa0fcQ",
				"y":"7oRiYhnmkP6nqrdXWgtsWUWq5uFRLJkhyVFiWPRB278",
				"use":"sig", "alg":"SS256", "key_ops":["verify"],
				"kid":"EhuduQ"}]
			}`,
		},
		{
			tag: "invalid algorithm",
			jwkSet: `{
				"keys":[{
				"kty":"EC",
				"crv":"P-256",
				"x":"wO6uIxh8SkKOO8VjZXNRTteRcwCPE4_4JElKyaa0fcQ",
				"y":"7oRiYhnmkP6nqrdXWgtsWUWq5uFRLJkhyVFiWPRB278",
				"use":"sig","alg":"ES257","key_ops":["verify"],
				"kid":"EhuduQ"}]
			}`,
		},
		{
			tag: "algorithm not a string",
			jwkSet: `{
				"keys":[{
				"kty":"EC",
				"crv":"P-256",
				"x":"wO6uIxh8SkKOO8VjZXNRTteRcwCPE4_4JElKyaa0fcQ",
				"y":"7oRiYhnmkP6nqrdXWgtsWUWq5uFRLJkhyVFiWPRB278",
				"use":"sig","alg":256,"key_ops":["verify"],
				"kid":"EhuduQ"}]
			}`,
		},
		{
			tag: "invalid curve and algorithm",
			jwkSet: `{
				"keys":[{
				"kty":"EC",
				"crv":"P-384",
				"x":"wO6uIxh8SkKOO8VjZXNRTteRcwCPE4_4JElKyaa0fcQ",
				"y":"7oRiYhnmkP6nqrdXWgtsWUWq5uFRLJkhyVFiWPRB278",
				"use":"sig","alg":"ES512","key_ops":["verify"],
				"kid":"EhuduQ"}]
			}`,
		},
		{
			tag: "without curve",
			jwkSet: `{
				"keys":[{
				"kty":"EC",
				"x":"wO6uIxh8SkKOO8VjZXNRTteRcwCPE4_4JElKyaa0fcQ",
				"y":"7oRiYhnmkP6nqrdXWgtsWUWq5uFRLJkhyVFiWPRB278",
				"use":"sig","alg":"ES512","key_ops":["verify"],
				"kid":"EhuduQ"}]
			}`,
		},
		{
			tag: "invalid key ops",
			jwkSet: `{
				"keys":[{
				"kty":"EC",
				"crv":"P-256",
				"x":"wO6uIxh8SkKOO8VjZXNRTteRcwCPE4_4JElKyaa0fcQ",
				"y":"7oRiYhnmkP6nqrdXWgtsWUWq5uFRLJkhyVFiWPRB278",
				"use":"sig","alg":"ES256","key_ops":["verify "],
				"kid":"EhuduQ"}]
			}`,
		},
		{
			tag: "multiple key ops",
			jwkSet: `{
				"keys":[{
				"kty":"EC",
				"crv":"P-256",
				"x":"wO6uIxh8SkKOO8VjZXNRTteRcwCPE4_4JElKyaa0fcQ",
				"y":"7oRiYhnmkP6nqrdXWgtsWUWq5uFRLJkhyVFiWPRB278",
				"use":"sig","alg":"ES256","key_ops":["verify", "sign"],
				"kid":"EhuduQ"}]
			}`,
		},
		{
			tag: "invalid key ops type",
			jwkSet: `{
				"keys":[{
				"kty":"EC",
				"crv":"P-256",
				"x":"wO6uIxh8SkKOO8VjZXNRTteRcwCPE4_4JElKyaa0fcQ",
				"y":"7oRiYhnmkP6nqrdXWgtsWUWq5uFRLJkhyVFiWPRB278",
				"use":"sig","alg":"ES256","key_ops":"verify",
				"kid":"EhuduQ"}]
			}`,
		},
		{
			tag: "invalid key ops type inside list",
			jwkSet: `{
				"keys":[{
				"kty":"EC",
				"crv":"P-256",
				"x":"wO6uIxh8SkKOO8VjZXNRTteRcwCPE4_4JElKyaa0fcQ",
				"y":"7oRiYhnmkP6nqrdXWgtsWUWq5uFRLJkhyVFiWPRB278",
				"use":"sig","alg":"ES256","key_ops":[1],
				"kid":"EhuduQ"}]
			}`,
		},
		{
			tag: "invalid use",
			jwkSet: `{
				"keys":[{
				"kty":"EC",
				"crv":"P-256",
				"x":"wO6uIxh8SkKOO8VjZXNRTteRcwCPE4_4JElKyaa0fcQ",
				"y":"7oRiYhnmkP6nqrdXWgtsWUWq5uFRLJkhyVFiWPRB278",
				"use":"zag","alg":"ES256","key_ops":["verify"],
				"kid":"EhuduQ"}]
			}`,
		},
		{
			tag: "without x coordinate",
			jwkSet: `{
				"keys":[{
				"kty":"EC",
				"crv":"P-256",
				"y":"7oRiYhnmkP6nqrdXWgtsWUWq5uFRLJkhyVFiWPRB278",
				"use":"sig","alg":"ES256","key_ops":["verify"],
				"kid":"EhuduQ"}]
			}`,
		},
		{
			tag: "without y coordinate",
			jwkSet: `{
				"keys":[{
				"kty":"EC",
				"crv":"P-256",
				"x":"wO6uIxh8SkKOO8VjZXNRTteRcwCPE4_4JElKyaa0fcQ",
				"use":"sig","alg":"ES256","key_ops":["verify"],
				"kid":"EhuduQ"}]
			}`,
		},
		{
			tag: "kid of invalid type",
			jwkSet: `{
			"keys":[{
			"kty":"EC",
			"crv":"P-256",
			"x":"wO6uIxh8SkKOO8VjZXNRTteRcwCPE4_4JElKyaa0fcQ",
			"y":"7oRiYhnmkP6nqrdXWgtsWUWq5uFRLJkhyVFiWPRB278",
			"use":"sig","alg":"ES256","key_ops":["verify"],
			"kid":5}]
			}`,
		},
		{
			tag: "with private key",
			jwkSet: `{
				"keys":[{
				"kty":"EC",
				"crv":"P-256",
				"alg":"ES256",
				"x":"SVqB4JcUD6lsfvqMr-OKUNUphdNn64Eay60978ZlL74",
				"y":"lf0u0pMj4lGAzZix5u4Cm5CMQIgMNpkwy163wtKYVKI",
				"d":"0g5vAEKzugrXaRbgKG0Tj2qJ5lMP4Bezds1_sTybkfk"
				}]
			}`,
		},
	} {
		t.Run(tc.tag, func(t *testing.T) {
			if _, err := jwt.JWKSetToPublicKeysetHandle([]byte(tc.jwkSet)); err == nil {
				t.Fatalf("jwt.JWKSetToPublicKeysetHandle() err = nil, want error")
			}
		})
	}
}

func TestJWKSetFromPublicKeysetNonEnabledKeysAreIgnored(t *testing.T) {
	key := `{
      "primaryKeyId": 303799737,
      "key": [
          {
              "keyId": 303799737,
              "status": "DISABLED",
              "outputPrefixType": "TINK",
              "keyData": {
                  "typeUrl": "type.googleapis.com/google.crypto.tink.JwtEcdsaPublicKey",
                  "keyMaterialType": "ASYMMETRIC_PUBLIC",
                  "value": "IiDuhGJiGeaQ/qeqt1daC2xZRarm4VEsmSHJUWJY9EHbvxogwO6uIxh8SkKOO8VjZXNRTteRcwCPE4/4JElKyaa0fcQQAQ=="
              }
          }
      ]
  }`
	handle, err := createKeysetHandle(key)
	if err != nil {
		t.Fatalf("createKeysetHandle() err = %v, want nil", err)
	}
	jwkSet, err := jwt.JWKSetFromPublicKeysetHandle(handle)
	if err != nil {
		t.Fatalf("jwt.JWKSetFromPublicKeysetHandle() err = %v, want nil", err)
	}
	want := `{"keys":[]}`
	if string(jwkSet) != want {
		t.Fatalf("jwt.JWKSetFromPublicKeysetHandle() = %q, want %q", string(jwkSet), want)
	}
}

func TestJWKSetFromPublicKeysetHandleTinkOutputPrefixHasKID(t *testing.T) {
	for _, tc := range []jwkSetTestCase{
		{
			tag: "JwtEcdsaPublicKey",
			publicKeyset: `{
					"primaryKeyId": 303799737,
					"key": [
							{
									"keyId": 303799737,
									"status": "ENABLED",
									"outputPrefixType": "TINK",
									"keyData": {
											"typeUrl": "type.googleapis.com/google.crypto.tink.JwtEcdsaPublicKey",
											"keyMaterialType": "ASYMMETRIC_PUBLIC",
											"value": "IiDuhGJiGeaQ/qeqt1daC2xZRarm4VEsmSHJUWJY9EHbvxogwO6uIxh8SkKOO8VjZXNRTteRcwCPE4/4JElKyaa0fcQQAQ=="
									}
							}
					]
			}`,
			jwkSet: `{
				"keys":[{
				"kty":"EC",
				"crv":"P-256",
				"x":"wO6uIxh8SkKOO8VjZXNRTteRcwCPE4_4JElKyaa0fcQ",
				"y":"7oRiYhnmkP6nqrdXWgtsWUWq5uFRLJkhyVFiWPRB278",
				"use":"sig",
				"alg":"ES256",
				"key_ops":["verify"],
				"kid":"EhuduQ"}]
			}`,
		},
		{
			tag: "JwtRsaSsaPkcs1PublicKey",
			publicKeyset: `{
				"primaryKeyId": 1277272603,
				"key": [
					{
						"keyData": {
							"typeUrl": "type.googleapis.com/google.crypto.tink.JwtRsaSsaPkcs1PublicKey",
							"value": "IgMBAAEagAK+ZQ5rrZNivGPs3ytlUDOgR1KeaxFBo1YEwB0Hxp0ZryfjJwaJhaga/S5lZzy8faOfqXc9r/vZtvYgd/f4oPZRpPAuTXHfJKFfJsShLlkX1t6bOufaiE2LEag3s5+PvA9vrVn4XU2/neerfTzP5EjVZ7Igf70eO4hy5TFpZjRV6+xfMJ6Ewk/mDuRXPKXnlthxGLbx2J2RVrOvNWA0bfnI00wQvfahbVV+++nuF9Ae3FLCQU4/MmDMg8dskVvEAsauuBceyirtS0NB1L2++gSnj8nNCEK2cIQpqGCRPA5bJP3o6VEZiI8lIUdZO6PLVCd3o4pzwsYSykBfigPpmX5hEAE=",
							"keyMaterialType": "ASYMMETRIC_PUBLIC"
						},
						"status": "ENABLED",
						"keyId": 1277272603,
						"outputPrefixType": "TINK"
					}
				]
			}`,
			jwkSet: `{
				"keys":[{
					"kty":"RSA",
					"n": "vmUOa62TYrxj7N8rZVAzoEdSnmsRQaNWBMAdB8adGa8n4ycGiYWoGv0uZWc8vH2jn6l3Pa_72bb2IHf3-KD2UaTwLk1x3yShXybEoS5ZF9bemzrn2ohNixGoN7Ofj7wPb61Z-F1Nv53nq308z-RI1WeyIH-9HjuIcuUxaWY0VevsXzCehMJP5g7kVzyl55bYcRi28didkVazrzVgNG35yNNMEL32oW1Vfvvp7hfQHtxSwkFOPzJgzIPHbJFbxALGrrgXHsoq7UtDQdS9vvoEp4_JzQhCtnCEKahgkTwOWyT96OlRGYiPJSFHWTujy1Qnd6OKc8LGEspAX4oD6Zl-YQ",
					"e":"AQAB",
					"use":"sig",
					"alg":"RS256",
					"key_ops":["verify"],
					"kid":"TCGiGw"
				}]
			}`,
		},
	} {
		t.Run(tc.tag, func(t *testing.T) {
			handle, err := createKeysetHandle(tc.publicKeyset)
			if err != nil {
				t.Fatalf("createKeysetHandle() err = %v, want nil", err)
			}
			js, err := jwt.JWKSetFromPublicKeysetHandle(handle)
			if err != nil {
				t.Fatalf("jwt.JWKSetFromPublicKeysetHandle() err = %v, want nil", err)
			}
			got := &spb.Struct{}
			if err := got.UnmarshalJSON(js); err != nil {
				t.Fatalf("got.UnmarshalJSON() err = %v, want nil", err)
			}
			want := &spb.Struct{}
			if err := want.UnmarshalJSON([]byte(tc.jwkSet)); err != nil {
				t.Fatalf("want.UnmarshalJSON() err = %v, want nil", err)
			}
			if !cmp.Equal(want, got, protocmp.Transform()) {
				t.Errorf("mismatch in jwk sets: diff (-want,+got): %v", cmp.Diff(want, got, protocmp.Transform()))
			}
		})
	}
}

func TestJWKSetFromPublicKeysetHandleInvalidKeysetsFails(t *testing.T) {
	for _, tc := range []jwkSetTestCase{
		{
			tag: "invalid output prefix",
			publicKeyset: `{
      "primaryKeyId": 303799737,
      "key": [
          {
              "keyId": 303799737,
              "status": "ENABLED",
              "outputPrefixType": "LEGACY",
              "keyData": {
                  "typeUrl": "type.googleapis.com/google.crypto.tink.JwtEcdsaPublicKey",
                  "keyMaterialType": "ASYMMETRIC_PUBLIC",
                  "value": "IiDuhGJiGeaQ/qeqt1daC2xZRarm4VEsmSHJUWJY9EHbvxogwO6uIxh8SkKOO8VjZXNRTteRcwCPE4/4JElKyaa0fcQQAQ=="
              }
          }
      ]
  	}`,
		},
		{
			tag: "JwtEcdsaPublicKey unknown algorithm", // The algorithm is set in the base64 encoded value of the key data.
			publicKeyset: `{
			"primaryKeyId": 303799737,
			"key": [
				{
					"keyId": 303799737,
					"status": "ENABLED",
					"outputPrefixType": "TINK",
					"keyData": {
						"typeUrl": "type.googleapis.com/google.crypto.tink.JwtEcdsaPublicKey",
						"value": "IiDuhGJiGeaQ/qeqt1daC2xZRarm4VEsmSHJUWJY9EHbvxogwO6uIxh8SkKOO8VjZXNRTteRcwCPE4/4JElKyaa0fcQ=",
						"keyMaterialType": "ASYMMETRIC_PUBLIC"
					}
				}
			]
		}`,
		},
		{
			tag: "private ecdsa keyset",
			publicKeyset: `{
      "primaryKeyId": 303799737,
      "key": [
          {
              "keyId": 303799737,
              "status": "ENABLED",
              "outputPrefixType": "TINK",
              "keyData": {
                  "typeUrl": "type.googleapis.com/google.crypto.tink.JwtEcdsaPublicKey",
                  "keyMaterialType": "ASYMMETRIC_PRIVATE",
                  "value": "IiDuhGJiGeaQ/qeqt1daC2xZRarm4VEsmSHJUWJY9EHbvxogwO6uIxh8SkKOO8VjZXNRTteRcwCPE4/4JElKyaa0fcQQAQ=="
              }
          }
      ]
  }`,
		},
		{
			tag: "unknown key type",
			publicKeyset: `{
      "primaryKeyId": 303799737,
      "key": [
          {
              "keyId": 303799737,
              "status": "ENABLED",
              "outputPrefixType": "TINK",
              "keyData": {
                  "typeUrl": "type.googleapis.com/google.crypto.tink.Unknown",
                  "keyMaterialType": "ASYMMETRIC_PUBLIC",
                  "value": "IiDuhGJiGeaQ/qeqt1daC2xZRarm4VEsmSHJUWJY9EHbvxogwO6uIxh8SkKOO8VjZXNRTteRcwCPE4/4JElKyaa0fcQQAQ=="
              }
          }
      ]
  }`,
		},
		{
			tag: "JwtRsaSsaPkcs1 unknown algorithm", // The algorithm is set in the base64 encoded value of the key data.
			publicKeyset: `{
				"primaryKeyId": 1277272603,
				"key": [
					{
						"keyData": {
							"typeUrl": "type.googleapis.com/google.crypto.tink.JwtRsaSsaPkcs1PublicKey",
							"value": "IgMBAAEagAK+ZQ5rrZNivGPs3ytlUDOgR1KeaxFBo1YEwB0Hxp0ZryfjJwaJhaga/S5lZzy8faOfqXc9r/vZtvYgd/f4oPZRpPAuTXHfJKFfJsShLlkX1t6bOufaiE2LEag3s5+PvA9vrVn4XU2/neerfTzP5EjVZ7Igf70eO4hy5TFpZjRV6+xfMJ6Ewk/mDuRXPKXnlthxGLbx2J2RVrOvNWA0bfnI00wQvfahbVV+++nuF9Ae3FLCQU4/MmDMg8dskVvEAsauuBceyirtS0NB1L2++gSnj8nNCEK2cIQpqGCRPA5bJP3o6VEZiI8lIUdZO6PLVCd3o4pzwsYSykBfigPpmX5h",
							"keyMaterialType": "ASYMMETRIC_PUBLIC"
						},
						"status": "ENABLED",
						"keyId": 1277272603,
						"outputPrefixType": "TINK"
					}
				]
			}`,
		},
	} {
		t.Run(tc.tag, func(t *testing.T) {
			handle, err := createKeysetHandle(tc.publicKeyset)
			if err != nil {
				t.Fatalf("createKeysetHandle() err = %v, want nil", err)
			}
			if _, err := jwt.JWKSetFromPublicKeysetHandle(handle); err == nil {
				t.Errorf("jwt.JWKSetFromPublicKeysetHandle() err = nil, want error")
			}
		})
	}
}
