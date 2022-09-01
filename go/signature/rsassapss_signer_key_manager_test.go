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

// TODO(b/173082704): make public once key manager registered.
package signature

import (
	"testing"

	"google.golang.org/protobuf/proto"
	"github.com/google/tink/go/subtle/random"
	"github.com/google/tink/go/tink"
	cpb "github.com/google/tink/go/proto/common_go_proto"
	rsppb "github.com/google/tink/go/proto/rsa_ssa_pss_go_proto"
	tpb "github.com/google/tink/go/proto/tink_go_proto"
)

const (
	rsaPSSTestPrivateKeyTypeURL = "type.googleapis.com/google.crypto.tink.RsaSsaPssPrivateKey"
)

func TestRSASSAPSSSignerGetPrimitive(t *testing.T) {
	skm := &rsaSSAPSSSignerKeyManager{}
	privKey, err := makeValidRSAPSSKey()
	if err != nil {
		t.Fatalf("makeValidRSAPSSKey() err = %v, want nil", err)
	}
	serializedPrivate, err := proto.Marshal(privKey)
	if err != nil {
		t.Fatalf("proto.Marshal() err = %v, want nil", err)
	}
	p, err := skm.Primitive(serializedPrivate)
	if err != nil {
		t.Fatalf("Primitive() err = %v, want nil", err)
	}
	signer := p.(tink.Signer)
	vkm := &rsaSSAPSSVerifierKeyManager{}
	serializedPublic, err := proto.Marshal(privKey.GetPublicKey())
	if err != nil {
		t.Fatalf("proto.Marshal() err = %v, want nil", err)
	}
	p, err = vkm.Primitive(serializedPublic)
	if err != nil {
		t.Fatalf("Primitive() err = %v, want nil", err)
	}
	verifier := p.(tink.Verifier)
	data := random.GetRandomBytes(80)
	signature, err := signer.Sign(data)
	if err != nil {
		t.Fatalf("Sign() err = %v, want nil", err)
	}
	if err := verifier.Verify(signature, data); err != nil {
		t.Fatalf("Verify() err = %v, want nil", err)
	}
}

func mergePrivPub(priv *rsppb.RsaSsaPssPrivateKey, pub *rsppb.RsaSsaPssPublicKey) *rsppb.RsaSsaPssPrivateKey {
	return &rsppb.RsaSsaPssPrivateKey{
		Version:   priv.GetVersion(),
		PublicKey: pub,
		D:         priv.GetD(),
		P:         priv.GetP(),
		Q:         priv.GetQ(),
		Dp:        priv.GetDp(),
		Dq:        priv.GetDq(),
		Crt:       priv.GetCrt(),
	}
}

func TestRSASSAPSSSignerGetPrimitiveWithInvalidInput(t *testing.T) {
	type testCase struct {
		tag     string
		privKey *rsppb.RsaSsaPssPrivateKey
	}
	skm := &rsaSSAPSSSignerKeyManager{}
	validPrivKey, err := makeValidRSAPSSKey()
	if err != nil {
		t.Fatalf("makeValidRSAPSSKey() err = %v, want nil", err)
	}
	for _, tc := range []testCase{
		{
			tag:     "empty private key",
			privKey: &rsppb.RsaSsaPssPrivateKey{},
		},
		{
			tag: "invalid private key version",
			privKey: &rsppb.RsaSsaPssPrivateKey{
				Version:   validPrivKey.GetVersion() + 1,
				PublicKey: validPrivKey.GetPublicKey(),
				D:         validPrivKey.GetD(),
				P:         validPrivKey.GetP(),
				Q:         validPrivKey.GetQ(),
				Dp:        validPrivKey.GetDp(),
				Dq:        validPrivKey.GetDq(),
				Crt:       validPrivKey.GetCrt(),
			},
		},
		{
			tag: "invalid private key D",
			privKey: &rsppb.RsaSsaPssPrivateKey{
				Version:   validPrivKey.GetVersion(),
				PublicKey: validPrivKey.GetPublicKey(),
				D:         nil,
				P:         validPrivKey.GetP(),
				Q:         validPrivKey.GetQ(),
				Dp:        validPrivKey.GetDp(),
				Dq:        validPrivKey.GetDq(),
				Crt:       validPrivKey.GetCrt(),
			},
		},
		{
			tag: "invalid private key P",
			privKey: &rsppb.RsaSsaPssPrivateKey{
				Version:   validPrivKey.GetVersion(),
				PublicKey: validPrivKey.GetPublicKey(),
				D:         validPrivKey.GetD(),
				P:         nil,
				Q:         validPrivKey.GetQ(),
				Dp:        validPrivKey.GetDp(),
				Dq:        validPrivKey.GetDq(),
				Crt:       validPrivKey.GetCrt(),
			},
		},
		{
			tag: "invalid private key Q",
			privKey: &rsppb.RsaSsaPssPrivateKey{
				Version:   validPrivKey.GetVersion(),
				PublicKey: validPrivKey.GetPublicKey(),
				D:         validPrivKey.GetD(),
				P:         validPrivKey.GetP(),
				Q:         nil,
				Dp:        validPrivKey.GetDp(),
				Dq:        validPrivKey.GetDq(),
				Crt:       validPrivKey.GetCrt(),
			},
		},
		{
			tag: "invalid private key Dp",
			privKey: &rsppb.RsaSsaPssPrivateKey{
				Version:   validPrivKey.GetVersion(),
				PublicKey: validPrivKey.GetPublicKey(),
				D:         validPrivKey.GetD(),
				P:         validPrivKey.GetP(),
				Q:         validPrivKey.GetQ(),
				Dp:        nil,
				Dq:        validPrivKey.GetDq(),
				Crt:       validPrivKey.GetCrt(),
			},
		},
		{
			tag: "invalid private key Dq",
			privKey: &rsppb.RsaSsaPssPrivateKey{
				Version:   validPrivKey.GetVersion(),
				PublicKey: validPrivKey.GetPublicKey(),
				D:         validPrivKey.GetD(),
				P:         validPrivKey.GetP(),
				Q:         validPrivKey.GetQ(),
				Dp:        validPrivKey.GetDp(),
				Dq:        nil,
				Crt:       validPrivKey.GetCrt(),
			},
		},
		{
			tag: "invalid private key Crt",
			privKey: &rsppb.RsaSsaPssPrivateKey{
				Version:   validPrivKey.GetVersion(),
				PublicKey: validPrivKey.GetPublicKey(),
				D:         validPrivKey.GetD(),
				P:         validPrivKey.GetP(),
				Q:         validPrivKey.GetQ(),
				Dp:        validPrivKey.GetDp(),
				Dq:        validPrivKey.GetDq(),
				Crt:       nil,
			},
		},
		{
			tag:     "empty public key",
			privKey: mergePrivPub(validPrivKey, &rsppb.RsaSsaPssPublicKey{}),
		},
		{
			tag: "invalid public key version",
			privKey: mergePrivPub(
				validPrivKey,
				&rsppb.RsaSsaPssPublicKey{
					Version: validPrivKey.GetPublicKey().GetVersion() + 1,
					Params:  validPrivKey.GetPublicKey().GetParams(),
					N:       validPrivKey.GetPublicKey().GetN(),
					E:       validPrivKey.GetPublicKey().GetE(),
				}),
		},
		{
			tag: "different sig and mgf1 hash functions",
			privKey: mergePrivPub(
				validPrivKey,
				&rsppb.RsaSsaPssPublicKey{
					Version: validPrivKey.GetPublicKey().GetVersion(),
					Params: &rsppb.RsaSsaPssParams{
						SigHash:    cpb.HashType_SHA256,
						Mgf1Hash:   cpb.HashType_SHA384,
						SaltLength: validPrivKey.GetPublicKey().GetParams().GetSaltLength(),
					},
					N: validPrivKey.GetPublicKey().GetN(),
					E: validPrivKey.GetPublicKey().GetE(),
				}),
		},
		{
			tag: "negative salt length",
			privKey: mergePrivPub(
				validPrivKey,
				&rsppb.RsaSsaPssPublicKey{
					Version: validPrivKey.GetPublicKey().GetVersion(),
					Params: &rsppb.RsaSsaPssParams{
						SigHash:    validPrivKey.GetPublicKey().GetParams().GetSigHash(),
						Mgf1Hash:   validPrivKey.GetPublicKey().GetParams().GetMgf1Hash(),
						SaltLength: -1,
					},
					N: validPrivKey.GetPublicKey().GetN(),
					E: validPrivKey.GetPublicKey().GetE(),
				}),
		},
		{
			tag: "invalid hash function",
			privKey: mergePrivPub(
				validPrivKey,
				&rsppb.RsaSsaPssPublicKey{
					Version: validPrivKey.GetPublicKey().GetVersion(),
					Params: &rsppb.RsaSsaPssParams{
						SigHash:    cpb.HashType_UNKNOWN_HASH,
						Mgf1Hash:   cpb.HashType_UNKNOWN_HASH,
						SaltLength: validPrivKey.GetPublicKey().GetParams().GetSaltLength(),
					},
					N: validPrivKey.GetPublicKey().GetN(),
					E: validPrivKey.GetPublicKey().GetE(),
				}),
		},
		{
			tag: "unsafe hash function",
			privKey: mergePrivPub(
				validPrivKey,
				&rsppb.RsaSsaPssPublicKey{
					Version: validPrivKey.GetPublicKey().GetVersion(),
					Params: &rsppb.RsaSsaPssParams{
						SigHash:    cpb.HashType_SHA1,
						Mgf1Hash:   cpb.HashType_SHA1,
						SaltLength: validPrivKey.GetPublicKey().GetParams().GetSaltLength(),
					},
					N: validPrivKey.GetPublicKey().GetN(),
					E: validPrivKey.GetPublicKey().GetE(),
				}),
		},
		{
			tag: "invalid modulus",
			privKey: mergePrivPub(
				validPrivKey,
				&rsppb.RsaSsaPssPublicKey{
					Version: validPrivKey.GetPublicKey().GetVersion(),
					Params:  validPrivKey.GetPublicKey().GetParams(),
					N:       []byte{0x00},
					E:       validPrivKey.GetPublicKey().GetE(),
				}),
		},
		{
			tag: "invalid exponent",
			privKey: mergePrivPub(
				validPrivKey,
				&rsppb.RsaSsaPssPublicKey{
					Version: validPrivKey.GetPublicKey().GetVersion(),
					Params:  validPrivKey.GetPublicKey().GetParams(),
					N:       validPrivKey.GetPublicKey().GetN(),
					E:       []byte{0x01},
				}),
		},
		{
			tag: "exponent larger than 64 bits",
			privKey: mergePrivPub(
				validPrivKey,
				&rsppb.RsaSsaPssPublicKey{
					Version: validPrivKey.GetPublicKey().GetVersion(),
					Params:  validPrivKey.GetPublicKey().GetParams(),
					N:       validPrivKey.GetPublicKey().GetN(),
					E:       random.GetRandomBytes(32),
				}),
		},
	} {
		t.Run(tc.tag, func(t *testing.T) {
			serializedPrivKey, err := proto.Marshal(tc.privKey)
			if err != nil {
				t.Fatalf("proto.Marshal() err = %v, want nil", err)
			}
			if _, err := skm.Primitive(serializedPrivKey); err == nil {
				t.Errorf("Primitive() err = nil, want error")
			}
			if _, err := skm.PublicKeyData(serializedPrivKey); err == nil {
				t.Errorf("PublicKeyData() err = nil, want error")
			}
		})
	}
}

func TestRSASSAPSSSignerGetPrimitiveWithCorruptedPrivateKey(t *testing.T) {
	skm := &rsaSSAPSSSignerKeyManager{}
	validPrivKey, err := makeValidRSAPSSKey()
	if err != nil {
		t.Fatalf("makeValidRSAPSSKey() err = %v, want nil", err)
	}
	corruptedPrivKey := validPrivKey
	corruptedPrivKey.P[5] <<= 1
	corruptedPrivKey.P[20] <<= 1
	serializedPrivKey, err := proto.Marshal(corruptedPrivKey)
	if err != nil {
		t.Fatalf("proto.Marshal() err = %v, want nil", err)
	}
	if _, err := skm.Primitive(serializedPrivKey); err == nil {
		t.Errorf("Primitive() err = nil, want error")
	}
}

func TestRSASSAPSSSignerPublicKeyData(t *testing.T) {
	skm := &rsaSSAPSSSignerKeyManager{}
	vkm := &rsaSSAPSSVerifierKeyManager{}
	validPrivKey, err := makeValidRSAPSSKey()
	if err != nil {
		t.Fatalf("makeValidRSAPSSKey() err = %v, want nil", err)
	}
	serializedPrivKey, err := proto.Marshal(validPrivKey)
	if err != nil {
		t.Fatalf("proto.Marshal() err = %v, want nil", err)
	}
	pubKeyData, err := skm.PublicKeyData(serializedPrivKey)
	if err != nil {
		t.Fatalf("PublicKeyData() err = %v, want nil", err)
	}
	if pubKeyData.GetKeyMaterialType() != tpb.KeyData_ASYMMETRIC_PUBLIC {
		t.Errorf("GetKeyMaterialType() = %v, want %v", pubKeyData.GetKeyMaterialType(), tpb.KeyData_ASYMMETRIC_PUBLIC)
	}
	if pubKeyData.GetTypeUrl() != rsaPSSTestPublicKeyTypeURL {
		t.Errorf("GetTypeUrl() = %q, want %q", pubKeyData.GetTypeUrl(), rsaPSSTestPublicKeyTypeURL)
	}
	if _, err := vkm.Primitive(pubKeyData.GetValue()); err != nil {
		t.Fatalf("vkm.Primitive() err = %v, want nil", err)
	}
}
