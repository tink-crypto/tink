//https://github.com/obscuren/ecies
//https://github.com/ethereum/go-ethereum/blob/master/crypto/ecies/ecies.go
package subtle

import (
	"bytes"
	"crypto/elliptic"
	"crypto/rand"
	"flag"
	"fmt"
	"io/ioutil"
	"testing"
)

var dumpEnc bool

func init() {
	flDump := flag.Bool("dump", false, "write encrypted test message to file")
	flag.Parse()
	dumpEnc = *flDump
}

var skLen int
var ErrBadSharedKeys = fmt.Errorf("ecies: shared keys don't match")

// cmpParams compares a set of ECIES parameters. We assume, as per the
// docs, that AES is the only supported symmetric encryption algorithm.
func cmpParams(p1, p2 *ECIESParams) bool {
	if p1.hashAlgo != p2.hashAlgo {
		return false
	} else if p1.KeyLen != p2.KeyLen {
		return false
	} else if p1.BlockSize != p2.BlockSize {
		return false
	}
	return true
}

// cmpPublic returns true if the two public keys represent the same pojnt.
func cmpPublic(pub1, pub2 EllipticPublicKey) bool {
	if pub1.X == nil || pub1.Y == nil {
		fmt.Println(ErrInvalidPublicKey.Error())
		return false
	}
	if pub2.X == nil || pub2.Y == nil {
		fmt.Println(ErrInvalidPublicKey.Error())
		return false
	}
	pub1Out := elliptic.Marshal(pub1.Curve, pub1.X, pub1.Y)
	pub2Out := elliptic.Marshal(pub2.Curve, pub2.X, pub2.Y)

	return bytes.Equal(pub1Out, pub2Out)
}

// cmpPrivate returns true if the two private keys are the same.
func cmpPrivate(prv1, prv2 *EllipticPrivateKey) bool {
	if prv1 == nil || prv1.D == nil {
		return false
	} else if prv2 == nil || prv2.D == nil {
		return false
	} else if prv1.D.Cmp(prv2.D) != 0 {
		return false
	} else {
		return cmpPublic(prv1.EllipticPublicKey, prv2.EllipticPublicKey)
	}
}

// Validate the ECDH component.
func TestSharedKey(t *testing.T) {
	prv1, err := GenerateKey(rand.Reader, DefaultCurve, nil)
	if err != nil {
		fmt.Println(err.Error())
		t.FailNow()
	}
	skLen = MaxSharedKeyLength(&prv1.EllipticPublicKey) / 2

	prv2, err := GenerateKey(rand.Reader, DefaultCurve, nil)
	if err != nil {
		fmt.Println(err.Error())
		t.FailNow()
	}

	sk1, err := prv1.GenerateShared(&prv2.EllipticPublicKey, skLen, skLen)
	if err != nil {
		fmt.Println(err.Error())
		t.FailNow()
	}

	sk2, err := prv2.GenerateShared(&prv1.EllipticPublicKey, skLen, skLen)
	if err != nil {
		fmt.Println(err.Error())
		t.FailNow()
	}

	if !bytes.Equal(sk1, sk2) {
		fmt.Println(ErrBadSharedKeys.Error())
		t.FailNow()
	}
}

// Verify that the key generation code fails when too much key data is
// requested.
func TestTooBigSharedKey(t *testing.T) {
	prv1, err := GenerateKey(rand.Reader, DefaultCurve, nil)
	if err != nil {
		fmt.Println(err.Error())
		t.FailNow()
	}

	prv2, err := GenerateKey(rand.Reader, DefaultCurve, nil)
	if err != nil {
		fmt.Println(err.Error())
		t.FailNow()
	}

	_, err = prv1.GenerateShared(&prv2.EllipticPublicKey, skLen*2, skLen*2)
	if err != ErrSharedKeyTooBig {
		fmt.Println("ecdh: shared key should be too large for curve")
		t.FailNow()
	}

	_, err = prv2.GenerateShared(&prv1.EllipticPublicKey, skLen*2, skLen*2)
	if err != ErrSharedKeyTooBig {
		fmt.Println("ecdh: shared key should be too large for curve")
		t.FailNow()
	}
}

// Ensure a public key can be successfully marshalled and unmarshalled, and
// that the decoded key is the same as the original.
func TestMarshalPublic(t *testing.T) {
	prv, err := GenerateKey(rand.Reader, DefaultCurve, nil)
	if err != nil {
		fmt.Println(err.Error())
		t.FailNow()
	}

	out, err := MarshalPublic(&prv.EllipticPublicKey)
	if err != nil {
		fmt.Println(err.Error())
		t.FailNow()
	}

	pub, err := UnmarshalPublic(out)
	if err != nil {
		fmt.Println(err.Error())
		t.FailNow()
	}

	if !cmpPublic(prv.EllipticPublicKey, *pub) {
		fmt.Println("ecies: failed to unmarshal public key")
		t.FailNow()
	}
}

// Ensure that a private key can be encoded into DER format, and that
// the resulting key is properly parsed back into a public key.
func TestMarshalPrivate(t *testing.T) {
	prv, err := GenerateKey(rand.Reader, DefaultCurve, nil)
	if err != nil {
		fmt.Println(err.Error())
		t.FailNow()
	}

	out, err := MarshalPrivate(prv)
	if err != nil {
		fmt.Println(err.Error())
		t.FailNow()
	}

	if dumpEnc {
		ioutil.WriteFile("test.out", out, 0644)
	}

	prv2, err := UnmarshalPrivate(out)
	if err != nil {
		fmt.Println(err.Error())
		t.FailNow()
	}

	if !cmpPrivate(prv, prv2) {
		fmt.Println("ecdh: private key import failed")
		t.FailNow()
	}
}

// Ensure that a private key can be successfully encoded to PEM format, and
// the resulting key is properly parsed back in.
func TestPrivatePEM(t *testing.T) {
	prv, err := GenerateKey(rand.Reader, DefaultCurve, nil)
	if err != nil {
		fmt.Println(err.Error())
		t.FailNow()
	}

	out, err := ExportPrivatePEM(prv)
	if err != nil {
		fmt.Println(err.Error())
		t.FailNow()
	}

	if dumpEnc {
		ioutil.WriteFile("test.key", out, 0644)
	}

	prv2, err := ImportPrivatePEM(out)
	if err != nil {
		fmt.Println(err.Error())
		t.FailNow()
	} else if !cmpPrivate(prv, prv2) {
		fmt.Println("ecdh: import from PEM failed")
		t.FailNow()
	}
}

// Ensure that a public key can be successfully encoded to PEM format, and
// the resulting key is properly parsed back in.
func TestPublicPEM(t *testing.T) {
	prv, err := GenerateKey(rand.Reader, DefaultCurve, nil)
	if err != nil {
		fmt.Println(err.Error())
		t.FailNow()
	}

	out, err := ExportPublicPEM(&prv.EllipticPublicKey)
	if err != nil {
		fmt.Println(err.Error())
		t.FailNow()
	}

	if dumpEnc {
		ioutil.WriteFile("test.pem", out, 0644)
	}

	pub2, err := ImportPublicPEM(out)
	if err != nil {
		fmt.Println(err.Error())
		t.FailNow()
	} else if !cmpPublic(prv.EllipticPublicKey, *pub2) {
		fmt.Println("ecdh: import from PEM failed")
		t.FailNow()
	}
}

// Benchmark the generation of P256 keys.
func BenchmarkGenerateKeyP256(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if _, err := GenerateKey(rand.Reader, elliptic.P256(), nil); err != nil {
			fmt.Println(err.Error())
			b.FailNow()
		}
	}
}

// Benchmark the generation of P256 shared keys.
func BenchmarkGenSharedKeyP256(b *testing.B) {
	prv, err := GenerateKey(rand.Reader, elliptic.P256(), nil)
	if err != nil {
		fmt.Println(err.Error())
		b.FailNow()
	}

	for i := 0; i < b.N; i++ {
		_, err := prv.GenerateShared(&prv.EllipticPublicKey, skLen, skLen)
		if err != nil {
			fmt.Println(err.Error())
			b.FailNow()
		}
	}
}

type testCase struct {
	Curve    elliptic.Curve
	Name     string
	Expected bool
}

var testCases = []testCase{
	testCase{
		Curve:    elliptic.P224(),
		Name:     "P224",
		Expected: false,
	},
	testCase{
		Curve:    elliptic.P256(),
		Name:     "P256",
		Expected: true,
	},
	testCase{
		Curve:    elliptic.P384(),
		Name:     "P384",
		Expected: true,
	},
	testCase{
		Curve:    elliptic.P521(),
		Name:     "P521",
		Expected: true,
	},
}
