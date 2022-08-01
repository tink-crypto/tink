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
	"math/big"
	"testing"

	"github.com/google/go-cmp/cmp"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/signature/internal"
	"github.com/google/tink/go/subtle/random"
	cpb "github.com/google/tink/go/proto/common_go_proto"
	rsassapkcs1pb "github.com/google/tink/go/proto/rsa_ssa_pkcs1_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

const (
	rsaPKCS1PrivateKeyTypeURL = "type.googleapis.com/google.crypto.tink.RsaSsaPkcs1PrivateKey"
)

func TestRSASSAPKCS1SignerKeyManagerDoesSupport(t *testing.T) {
	skm, err := registry.GetKeyManager(rsaPKCS1PrivateKeyTypeURL)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", rsaPKCS1PrivateKeyTypeURL, err)
	}
	if !skm.DoesSupport(rsaPKCS1PrivateKeyTypeURL) {
		t.Errorf("DoesSupport(%q) = false, want true", rsaPKCS1PrivateKeyTypeURL)
	}
	if skm.DoesSupport("not.valid.type") {
		t.Errorf("DoesSupport(%q) = true, want false", "not.valid.type")
	}
}

func TestRSASSAPKCS1SignerTypeURL(t *testing.T) {
	skm, err := registry.GetKeyManager(rsaPKCS1PrivateKeyTypeURL)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", rsaPKCS1PrivateKeyTypeURL, err)
	}
	if skm.TypeURL() != rsaPKCS1PrivateKeyTypeURL {
		t.Errorf("TypeURL() = %q, want %q", skm.TypeURL(), rsaPKCS1PrivateKeyTypeURL)
	}
}

func TestRSASSAPKCS1SignerKeyManagerPublicData(t *testing.T) {
	skm, err := registry.GetKeyManager(rsaPKCS1PrivateKeyTypeURL)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", rsaPKCS1PrivateKeyTypeURL, err)
	}
	privKey, err := makeValidRSAPKCS1Key()
	if err != nil {
		t.Fatalf("makeValidRSAPKCS1Key() err = %v, want nil", err)
	}
	serializedPrivate, err := proto.Marshal(privKey)
	if err != nil {
		t.Fatalf("proto.Marshal() err = %v, want nil", err)
	}
	serializedPublic, err := proto.Marshal(privKey.PublicKey)
	if err != nil {
		t.Fatalf("proto.Marshal() err = %v, want nil", err)
	}
	got, err := skm.(registry.PrivateKeyManager).PublicKeyData(serializedPrivate)
	if err != nil {
		t.Fatalf("PublicKeyData() err = %v, want nil", err)
	}
	want := &tinkpb.KeyData{
		TypeUrl:         rsaPKCS1PublicTypeURL,
		KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
		Value:           serializedPublic,
	}
	if !cmp.Equal(got, want, protocmp.Transform()) {
		t.Errorf("got = %v, want = %v, with diff: %v", got, want, cmp.Diff(got, want, protocmp.Transform()))
	}
}

func TestRSASSAPKCS1SignerKeyManagerPublicDataFailsWithInvalidInput(t *testing.T) {
	type testCase struct {
		name   string
		pubKey *rsassapkcs1pb.RsaSsaPkcs1PublicKey
	}
	validPrivKey, err := makeValidRSAPKCS1Key()
	if err != nil {
		t.Fatalf("makeValidRSAPKCS1Key() err = %v, want nil", err)
	}
	skm, err := registry.GetKeyManager(rsaPKCS1PrivateKeyTypeURL)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", rsaPKCS1PrivateKeyTypeURL, err)
	}
	for _, tc := range []testCase{
		{
			name:   "nil public key",
			pubKey: nil,
		},
		{
			name: "invalid hash function",
			pubKey: &rsassapkcs1pb.RsaSsaPkcs1PublicKey{
				Version: validPrivKey.GetVersion(),
				Params: &rsassapkcs1pb.RsaSsaPkcs1Params{
					HashType: cpb.HashType_SHA1,
				},
				N: validPrivKey.GetPublicKey().GetN(),
				E: validPrivKey.GetPublicKey().GetE(),
			},
		},
		{
			name: "invalid exponent",
			pubKey: &rsassapkcs1pb.RsaSsaPkcs1PublicKey{
				Version: validPrivKey.GetVersion(),
				Params:  validPrivKey.GetPublicKey().GetParams(),
				N:       validPrivKey.GetPublicKey().GetN(),
				E:       []byte{0x08},
			},
		},
		{
			name: "invalid modulus",
			pubKey: &rsassapkcs1pb.RsaSsaPkcs1PublicKey{
				Version: validPrivKey.GetVersion(),
				Params:  validPrivKey.GetPublicKey().GetParams(),
				N:       []byte{0x00, 0x00, 0x00},
				E:       validPrivKey.GetPublicKey().GetE(),
			},
		},
		{
			name: "invalid version",
			pubKey: &rsassapkcs1pb.RsaSsaPkcs1PublicKey{
				Version: validPrivKey.GetVersion() + 1,
				Params:  validPrivKey.GetPublicKey().GetParams(),
				N:       validPrivKey.GetPublicKey().GetN(),
				E:       validPrivKey.GetPublicKey().GetE(),
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			InvalidPub := validPrivKey
			InvalidPub.PublicKey = tc.pubKey
			serializedPrivateKey, err := proto.Marshal(InvalidPub)
			if err != nil {
				t.Fatalf("proto.Marshal() err= %v, want nil", err)
			}
			if _, err := skm.(registry.PrivateKeyManager).PublicKeyData(serializedPrivateKey); err == nil {
				t.Fatalf("PublicKeyData() err = nil, want error")
			}
		})
	}
}

func TestRSASSAPKCS1SignerKeyManagerPrimitiveSignVerify(t *testing.T) {
	skm, err := registry.GetKeyManager(rsaPKCS1PrivateKeyTypeURL)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", rsaPKCS1PrivateKeyTypeURL, err)
	}
	privKey, err := makeValidRSAPKCS1Key()
	if err != nil {
		t.Fatalf("makeValidRSAPKCS1Key() err = %v, want nil", err)
	}
	serializedPrivate, err := proto.Marshal(privKey)
	if err != nil {
		t.Fatalf("proto.Marshal() err = %v, want nil", err)
	}
	p, err := skm.Primitive(serializedPrivate)
	if err != nil {
		t.Fatalf("Primitive() err = %v, want nil", err)
	}
	signer, ok := p.(*internal.RSA_SSA_PKCS1_Signer)
	if !ok {
		t.Fatalf("primitive is not of type RSA_SSA_PKCS1_Signer")
	}
	vkm, err := registry.GetKeyManager(rsaPKCS1PublicTypeURL)
	if err != nil {
		t.Fatalf("regitry.GetKeyManager(%q) err = %v, want nil", rsaPKCS1PublicTypeURL, err)
	}
	serializedPublic, err := proto.Marshal(privKey.PublicKey)
	if err != nil {
		t.Fatalf("Failed serializing public key proto: %v", err)
	}
	p, err = vkm.Primitive(serializedPublic)
	if err != nil {
		t.Fatalf("rsaSSAPKCS1VerifierKeyManager.Primitive() failed: %v", err)
	}
	v, ok := p.(*internal.RSA_SSA_PKCS1_Verifier)
	if !ok {
		t.Fatalf("primitve is not of type RSA_SSA_PKCS1_Verifier")
	}
	data := random.GetRandomBytes(1281)
	signature, err := signer.Sign(data)
	if err != nil {
		t.Fatalf("Sign() err = %v, want nil", err)
	}
	if err := v.Verify(signature, data); err != nil {
		t.Fatalf("Verify() err = %v, want nil", err)
	}
}

func TestRSASSAPKCS1SignerKeyManagerPrimitiveWithInvalidInputFails(t *testing.T) {
	km, err := registry.GetKeyManager(rsaPKCS1PrivateKeyTypeURL)
	if err != nil {
		t.Errorf("cannot obtain RSASSAPKCS1Signer key manager: %s", err)
	}
	validPrivKey, err := makeValidRSAPKCS1Key()
	if err != nil {
		t.Fatalf("makeValidRSAPKCS1Key() err = %v, want nil", err)
	}
	type testCase struct {
		name string
		key  *rsassapkcs1pb.RsaSsaPkcs1PrivateKey
	}
	for _, tc := range []testCase{
		{
			name: "empty key",
			key:  &rsassapkcs1pb.RsaSsaPkcs1PrivateKey{},
		},
		{
			name: "nil key",
			key:  nil,
		},
		{
			name: "invalid version",
			key: &rsassapkcs1pb.RsaSsaPkcs1PrivateKey{
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
			name: "invalid hash algorithm ",
			key: &rsassapkcs1pb.RsaSsaPkcs1PrivateKey{
				Version: validPrivKey.Version,
				PublicKey: &rsassapkcs1pb.RsaSsaPkcs1PublicKey{
					Version: validPrivKey.GetPublicKey().GetVersion(),
					E:       validPrivKey.GetPublicKey().GetE(),
					N:       validPrivKey.GetPublicKey().GetN(),
					Params: &rsassapkcs1pb.RsaSsaPkcs1Params{
						HashType: cpb.HashType_SHA224,
					},
				},
				D:   validPrivKey.GetD(),
				P:   validPrivKey.GetP(),
				Q:   validPrivKey.GetQ(),
				Dp:  validPrivKey.GetDp(),
				Dq:  validPrivKey.GetDq(),
				Crt: validPrivKey.GetCrt(),
			},
		},
		{
			name: "invalid modulus",
			key: &rsassapkcs1pb.RsaSsaPkcs1PrivateKey{
				Version: validPrivKey.Version,
				PublicKey: &rsassapkcs1pb.RsaSsaPkcs1PublicKey{
					Version: validPrivKey.GetPublicKey().GetVersion(),
					E:       validPrivKey.GetPublicKey().GetE(),
					N:       []byte{3, 4, 5},
					Params:  validPrivKey.GetPublicKey().GetParams(),
				},
				D:   validPrivKey.GetD(),
				P:   validPrivKey.GetP(),
				Q:   validPrivKey.GetQ(),
				Dp:  validPrivKey.GetDp(),
				Dq:  validPrivKey.GetDq(),
				Crt: validPrivKey.GetCrt(),
			},
		},
		{
			name: "invalid public key exponent",
			key: &rsassapkcs1pb.RsaSsaPkcs1PrivateKey{
				Version: validPrivKey.Version,
				PublicKey: &rsassapkcs1pb.RsaSsaPkcs1PublicKey{
					Version: validPrivKey.GetPublicKey().GetVersion(),
					E:       []byte{0x06},
					N:       validPrivKey.GetPublicKey().GetN(),
					Params:  validPrivKey.GetPublicKey().GetParams(),
				},
				D:   validPrivKey.GetD(),
				P:   validPrivKey.GetP(),
				Q:   validPrivKey.GetQ(),
				Dp:  validPrivKey.GetDp(),
				Dq:  validPrivKey.GetDq(),
				Crt: validPrivKey.GetCrt(),
			},
		},
		{
			name: "invalid private key",
			key: &rsassapkcs1pb.RsaSsaPkcs1PrivateKey{
				Version: validPrivKey.Version,
				PublicKey: &rsassapkcs1pb.RsaSsaPkcs1PublicKey{
					Version: validPrivKey.GetPublicKey().GetVersion(),
					E:       validPrivKey.GetPublicKey().GetE(),
					N:       validPrivKey.GetPublicKey().GetN(),
					Params:  validPrivKey.GetPublicKey().GetParams(),
				},
				D:   nil,
				P:   nil,
				Q:   nil,
				Dp:  validPrivKey.GetDp(),
				Dq:  validPrivKey.GetDq(),
				Crt: validPrivKey.GetCrt(),
			},
		},
		{
			name: "invalid precomputed values in private key",
			key: &rsassapkcs1pb.RsaSsaPkcs1PrivateKey{
				Version: validPrivKey.Version,
				PublicKey: &rsassapkcs1pb.RsaSsaPkcs1PublicKey{
					Version: validPrivKey.GetPublicKey().GetVersion(),
					E:       validPrivKey.GetPublicKey().GetE(),
					N:       validPrivKey.GetPublicKey().GetN(),
					Params:  validPrivKey.GetPublicKey().GetParams(),
				},
				D:   validPrivKey.GetD(),
				P:   validPrivKey.GetP(),
				Q:   validPrivKey.GetQ(),
				Dp:  nil,
				Dq:  nil,
				Crt: nil,
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			serializedKey, err := proto.Marshal(tc.key)
			if err != nil {
				t.Fatalf("proto.Marshal() err = %v, want nil", err)
			}
			if _, err := km.Primitive(serializedKey); err == nil {
				t.Errorf("Primitive() err = nil, want error")
			}
		})
	}
}

func TestRSASSAPKCS1SignerKeyManagerPrimitiveNewKey(t *testing.T) {
	km, err := registry.GetKeyManager(rsaPKCS1PrivateKeyTypeURL)
	if err != nil {
		t.Errorf("cannot obtain RSASSAPKCS1Signer key manager: %s", err)
	}
	validPrivKey, err := makeValidRSAPKCS1Key()
	if err != nil {
		t.Fatalf("makeValidRSAPKCS1Key() err = %v, want nil", err)
	}
	keyFormat := &rsassapkcs1pb.RsaSsaPkcs1KeyFormat{
		Params: &rsassapkcs1pb.RsaSsaPkcs1Params{
			HashType: cpb.HashType_SHA256,
		},
		ModulusSizeInBits: 3072,
		PublicExponent:    []byte{0x01, 0x00, 0x01},
	}
	serializedFormat, err := proto.Marshal(keyFormat)
	if err != nil {
		t.Fatalf("proto.Marshal() err = %v, want nil", err)
	}
	m, err := km.NewKey(serializedFormat)
	if err != nil {
		t.Fatalf("NewKey() err = %v, want nil", err)
	}
	privKey, ok := m.(*rsassapkcs1pb.RsaSsaPkcs1PrivateKey)
	if !ok {
		t.Fatalf("privateKey is not a RsaSsaPkcs1PrivateKey")
	}
	if privKey.GetVersion() != validPrivKey.GetVersion() {
		t.Errorf("GetVersion() = %d, want %d", privKey.GetVersion(), validPrivKey.GetVersion())
	}
	wantPubKey := validPrivKey.GetPublicKey()
	gotPubKey := privKey.GetPublicKey()
	if gotPubKey.GetParams().GetHashType() != wantPubKey.GetParams().GetHashType() {
		t.Errorf("GetHashType() = %v, want %v", gotPubKey.GetParams().GetHashType(), wantPubKey.GetParams().GetHashType())
	}
	if !cmp.Equal(gotPubKey.GetE(), wantPubKey.GetE()) {
		t.Errorf("GetE() = %v, want %v", gotPubKey.GetE(), wantPubKey.GetE())
	}
	gotModSize := new(big.Int).SetBytes(gotPubKey.GetN()).BitLen()
	if gotModSize != 3072 {
		t.Errorf("Modulus Size = %d, want %d", gotModSize, 3072)
	}
}

func TestRSASSAPKCS1SignerKeyManagerPrimitiveNewKeyWithInvalidInputFails(t *testing.T) {
	type testCase struct {
		name   string
		format *rsassapkcs1pb.RsaSsaPkcs1KeyFormat
	}
	km, err := registry.GetKeyManager(rsaPKCS1PrivateKeyTypeURL)
	if err != nil {
		t.Errorf("cannot obtain RSASSAPKCS1Signer key manager: %s", err)
	}
	for _, tc := range []testCase{
		{
			name:   "empty format",
			format: &rsassapkcs1pb.RsaSsaPkcs1KeyFormat{},
		},
		{
			name: "invalid hash",
			format: &rsassapkcs1pb.RsaSsaPkcs1KeyFormat{
				ModulusSizeInBits: 2048,
				PublicExponent:    []byte{0x01, 0x00, 0x01},
				Params: &rsassapkcs1pb.RsaSsaPkcs1Params{
					HashType: cpb.HashType_SHA224,
				},
			},
		},
		{
			name: "invalid public exponent",
			format: &rsassapkcs1pb.RsaSsaPkcs1KeyFormat{
				ModulusSizeInBits: 2048,
				PublicExponent:    []byte{0x01},
				Params: &rsassapkcs1pb.RsaSsaPkcs1Params{
					HashType: cpb.HashType_SHA256,
				},
			},
		},
		{
			name: "invalid modulus size",
			format: &rsassapkcs1pb.RsaSsaPkcs1KeyFormat{
				ModulusSizeInBits: 1024,
				PublicExponent:    []byte{0x01},
				Params: &rsassapkcs1pb.RsaSsaPkcs1Params{
					HashType: cpb.HashType_SHA256,
				},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			serializedFormat, err := proto.Marshal(tc.format)
			if err != nil {
				t.Fatalf("proto.Marshal() err = %v, want nil", err)
			}
			if _, err := km.NewKey(serializedFormat); err == nil {
				t.Fatalf("NewKey() err = nil, want error")
			}
		})
	}
}

func TestRSASSAPKCS1SignerKeyManagerPrimitiveNewKeyData(t *testing.T) {
	km, err := registry.GetKeyManager(rsaPKCS1PrivateKeyTypeURL)
	if err != nil {
		t.Errorf("cannot obtain RSASSAPKCS1Signer key manager: %s", err)
	}
	keyFormat := &rsassapkcs1pb.RsaSsaPkcs1KeyFormat{
		ModulusSizeInBits: 2048,
		PublicExponent:    []byte{0x01, 0x00, 0x01},
		Params: &rsassapkcs1pb.RsaSsaPkcs1Params{
			HashType: cpb.HashType_SHA256,
		},
	}
	serializedFormat, err := proto.Marshal(keyFormat)
	if err != nil {
		t.Fatalf("proto.Marshal() err = %v, want nil", err)
	}
	keyData, err := km.NewKeyData(serializedFormat)
	if err != nil {
		t.Fatalf("NewKeyData() err = %v, want nil", err)
	}
	if keyData.GetTypeUrl() != rsaPKCS1PrivateKeyTypeURL {
		t.Fatalf("GetTypeUrl() = %v, want %v", keyData.GetTypeUrl(), rsaPKCS1PrivateKeyTypeURL)
	}
	if keyData.GetKeyMaterialType() != tinkpb.KeyData_ASYMMETRIC_PRIVATE {
		t.Fatalf("GetKeyMaterialType() = %v, want %v", keyData.GetKeyMaterialType(), tinkpb.KeyData_ASYMMETRIC_PRIVATE)
	}
}
