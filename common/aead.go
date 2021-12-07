package common

import (
	"crypto/aes"
	"crypto/cipher"
)

func AES_256_GCM_encrypt(plaintext []byte, nonce []byte, signature [32]byte, key [32]byte) ([]byte, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return aesgcm.Seal(nil, nonce, plaintext, signature[:]), nil
}

func AES_256_GCM_decrypt(ciphertext []byte, nonce []byte, signature [32]byte, key [32]byte) ([]byte, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	aesgcm.Overhead()
	return aesgcm.Open(nil, nonce, ciphertext, signature[:])
}
