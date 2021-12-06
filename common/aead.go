package common

import (
	"crypto/aes"
	"crypto/cipher"
)

func AES_256_GCM_encrypt(plaintext []byte, nonce []byte, signature [32]byte, key [32]byte) []byte {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		panic(err.Error())
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	return aesgcm.Seal(nil, nonce, plaintext, signature[:])
}

func AES_256_GCM_decrypt(ciphertext []byte, nonce []byte, signature [32]byte, key [32]byte) ([]byte, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		panic(err.Error())
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	aesgcm.Overhead()
	return aesgcm.Open(nil, nonce, ciphertext, signature[:])
}
