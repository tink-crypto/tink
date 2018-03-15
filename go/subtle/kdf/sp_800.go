package kdf

//Taken from golang ethereum project

import (
	"fmt"
	"hash"
	"math/big"
)

type SP_800 struct{}

var (
	big2To32          = new(big.Int).Exp(big.NewInt(2), big.NewInt(32), nil)
	big2To32M1        = new(big.Int).Sub(big2To32, big.NewInt(1))
	ErrKeyDataTooLong = fmt.Errorf("can't supply requested key data")
)

func incCounter(ctr []byte) {
	if ctr[3]++; ctr[3] != 0 {
		return
	} else if ctr[2]++; ctr[2] != 0 {
		return
	} else if ctr[1]++; ctr[1] != 0 {
		return
	} else if ctr[0]++; ctr[0] != 0 {
		return
	}
	return
}

// NIST SP 800-56 Concatenation Key Derivation Function (see section 5.8.1).
func (*SP_800) ConcatKDF(hash hash.Hash, z, s1 []byte, kdLen int) (k []byte, err error) {
	if s1 == nil {
		s1 = make([]byte, 0)
	}

	reps := ((kdLen + 7) * 8) / (hash.BlockSize() * 8)
	if big.NewInt(int64(reps)).Cmp(big2To32M1) > 0 {
		fmt.Println(big2To32M1)
		return nil, ErrKeyDataTooLong
	}

	counter := []byte{0, 0, 0, 1}
	k = make([]byte, 0)

	for i := 0; i <= reps; i++ {
		hash.Write(counter)
		hash.Write(z)
		hash.Write(s1)
		k = append(k, hash.Sum(nil)...)
		hash.Reset()
		incCounter(counter)
	}

	k = k[:kdLen]
	return
}
