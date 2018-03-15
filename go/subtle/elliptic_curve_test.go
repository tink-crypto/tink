package subtle

// Validate the ECDH component.
import (
	"bytes"
	"crypto/rand"
	"fmt"
	"testing"
)

var skLen int

func TestSharedKey(t *testing.T) {
	prv1, err := GenerateKey(rand.Reader, DefaultCurve)
	if err != nil {
		fmt.Println(err.Error())
		t.FailNow()
	}
	skLen = MaxSharedKeyLength(&prv1.EllipticPublicKey) / 2

	prv2, err := GenerateKey(rand.Reader, DefaultCurve)
	if err != nil {
		fmt.Println(err.Error())
		t.FailNow()
	}

	sk1, err := prv1.GenerateShared(&prv2.EllipticPublicKey, skLen+skLen)
	if err != nil {
		fmt.Println(err.Error())
		t.FailNow()
	}

	sk2, err := prv2.GenerateShared(&prv1.EllipticPublicKey, skLen+skLen)
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
	prv1, err := GenerateKey(rand.Reader, DefaultCurve)
	if err != nil {
		fmt.Println(err.Error())
		t.FailNow()
	}

	prv2, err := GenerateKey(rand.Reader, DefaultCurve)
	if err != nil {
		fmt.Println(err.Error())
		t.FailNow()
	}

	_, err = prv1.GenerateShared(&prv2.EllipticPublicKey, skLen*2+skLen*2)
	if err != ErrSharedKeyTooBig {
		fmt.Println("ecdh: shared key should be too large for curve")
		t.FailNow()
	}

	_, err = prv2.GenerateShared(&prv1.EllipticPublicKey, skLen*2+skLen*2)
	if err != ErrSharedKeyTooBig {
		fmt.Println("ecdh: shared key should be too large for curve")
		t.FailNow()
	}
}
