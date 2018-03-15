package kdf

// Generate an initialisation vector for CTR mode.
import "io"

func generateIV(keySize int, rand io.Reader) (iv []byte, err error) {
	iv = make([]byte, keySize)
	_, err = io.ReadFull(rand, iv)
	return
}
