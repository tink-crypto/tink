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

	internal "github.com/google/tink/go/internal/signature"
)

func TestValidatePublicExponent(t *testing.T) {
	if err := internal.RSAValidPublicExponent(65537); err != nil {
		t.Errorf("ValidPublicExponent(65537) err = %v, want nil", err)
	}
}

func TestValidateInvalidPublicExponentFails(t *testing.T) {
	if err := internal.RSAValidPublicExponent(3); err == nil {
		t.Errorf("ValidPublicExponent(3) err = nil, want error")
	}
}

func TestValidateModulusSizeInBits(t *testing.T) {
	if err := internal.RSAValidModulusSizeInBits(2048); err != nil {
		t.Errorf("ValidModulusSizeInBits(2048) err = %v, want nil", err)
	}
}

func TestValidateInvalidModulusSizeInBitsFails(t *testing.T) {
	if err := internal.RSAValidModulusSizeInBits(1024); err == nil {
		t.Errorf("ValidModulusSizeInBits(1024) err = nil, want error")
	}
}

func TestHashSafeForSignature(t *testing.T) {
	for _, h := range []string{
		"SHA256",
		"SHA384",
		"SHA512",
	} {
		t.Run(h, func(t *testing.T) {
			if err := internal.HashSafeForSignature(h); err != nil {
				t.Errorf("HashSafeForSignature(%q)  err = %v, want nil", h, err)
			}
		})
	}
}

func TestHashNotSafeForSignatureFails(t *testing.T) {
	for _, h := range []string{
		"SHA1",
		"SHA224",
		"MD5",
	} {
		t.Run(h, func(t *testing.T) {
			if err := internal.HashSafeForSignature(h); err == nil {
				t.Errorf("HashSafeForSignature(%q)  err = nil, want error", h)
			}
		})
	}
}

func TestRSAKeySelfTestWithCorruptedKeysFails(t *testing.T) {
	validPrivKey, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatalf("rsa.GenerateKey(rand.Reader, 3072) err = %v, want nil", err)
	}
	if err := internal.Validate_RSA_SSA_PKCS1("SHA256", validPrivKey); err != nil {
		t.Errorf("internal.Validate_RSA_SSA_PKCS1('SHA256', validPrivKey) err = %v, want nil", err)
	}
	saltLen := 0
	if err := internal.Validate_RSA_SSA_PSS("SHA256", saltLen, validPrivKey); err != nil {
		t.Errorf("internal.Validate_RSA_SSA_PSS('SHA256', saltLen, validPrivKey) err = %v, want nil", err)
	}
	type testCase struct {
		tag  string
		key  *rsa.PrivateKey
		hash string
	}
	for _, tc := range []testCase{
		{
			tag: "modify public modulus",
			key: &rsa.PrivateKey{
				D:           validPrivKey.D,
				Primes:      validPrivKey.Primes,
				Precomputed: validPrivKey.Precomputed,
				PublicKey: rsa.PublicKey{
					N: validPrivKey.N.Add(validPrivKey.N, big.NewInt(500)),
					E: validPrivKey.E,
				},
			},
		},
		{
			tag: "modify public exponent",
			key: &rsa.PrivateKey{
				D:           validPrivKey.D,
				Primes:      validPrivKey.Primes,
				Precomputed: validPrivKey.Precomputed,
				PublicKey: rsa.PublicKey{
					N: validPrivKey.N,
					E: validPrivKey.E + 5,
				},
			},
		},
		{
			tag: "one byte shift in Q",
			key: &rsa.PrivateKey{
				PublicKey:   validPrivKey.PublicKey,
				D:           validPrivKey.D,
				Precomputed: validPrivKey.Precomputed,
				Primes: []*big.Int{
					func() *big.Int {
						p := validPrivKey.Primes[0].Bytes()
						p[4] = byte(uint8(p[4] + 1))
						return new(big.Int).SetBytes(p)
					}(),
					validPrivKey.Primes[1],
				},
			},
			hash: "SHA256",
		},
		{
			tag: "removing one byte from P",
			key: &rsa.PrivateKey{
				PublicKey:   validPrivKey.PublicKey,
				D:           validPrivKey.D,
				Precomputed: validPrivKey.Precomputed,
				Primes: []*big.Int{
					validPrivKey.Primes[0],
					func() *big.Int {
						p := validPrivKey.Primes[1].Bytes()
						return new(big.Int).SetBytes(p[:len(p)-2])
					}(),
				},
			},
			hash: "SHA256",
		},
	} {
		t.Run(tc.tag, func(t *testing.T) {
			if err := internal.Validate_RSA_SSA_PKCS1(tc.hash, tc.key); err == nil {
				t.Errorf("internal.Validate_RSA_SSA_PKCS1(hash = %q, key) err = nil, want error", tc.hash)
			}
			if err := internal.Validate_RSA_SSA_PSS(tc.hash, saltLen, tc.key); err == nil {
				t.Errorf("internal.Validate_RSA_SSA_PSS(hash = %d saltLen = %q, key) err = nil, want error", saltLen, tc.hash)
			}
		})
	}
}
