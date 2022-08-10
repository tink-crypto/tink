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
	"math/big"
	"testing"

	"google.golang.org/protobuf/proto"
	"github.com/google/tink/go/core/registry"
	internal "github.com/google/tink/go/internal/signature"
	"github.com/google/tink/go/subtle/random"
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
