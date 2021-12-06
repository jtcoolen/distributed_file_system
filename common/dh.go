package common

import (
	"crypto/elliptic"
	"crypto/rand"
	"math/big"
)

type ECDHKeyPair struct {
	PrivateKey *big.Int
	PublicKeyX *big.Int
	PublicKeyY *big.Int
}

func GenKeyPair() (*ECDHKeyPair, error) {
	max := big.NewInt(0)
	max.Sub(elliptic.P521().Params().N, big.NewInt(1))
	privateKey, err := rand.Int(rand.Reader, max)
	if err != nil {
		return nil, err
	}
	privateKey.Add(privateKey, big.NewInt(1))

	pkX, pkY := elliptic.P521().ScalarMult(
		elliptic.P521().Params().Gx,
		elliptic.P521().Params().Gy,
		privateKey.Bytes())
	return &ECDHKeyPair{PrivateKey: privateKey, PublicKeyX: pkX, PublicKeyY: pkY}, nil
}

func GenSessionKey(publicKeyX *big.Int, publicKeyY *big.Int, privateKey *big.Int) (*big.Int, *big.Int) {
	return elliptic.P521().ScalarMult(publicKeyX, publicKeyY, privateKey.Bytes())
}
