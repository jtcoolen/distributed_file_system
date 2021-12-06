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
	var max *big.Int = big.NewInt(0)
	max.Sub(elliptic.P521().Params().N, big.NewInt(1))
	private_key, err := rand.Int(rand.Reader, max)
	if err != nil {
		return nil, err
	}
	private_key.Add(private_key, big.NewInt(1))

	pkX, pkY := elliptic.P521().ScalarMult(
		elliptic.P521().Params().Gx,
		elliptic.P521().Params().Gy,
		private_key.Bytes())
	return &ECDHKeyPair{private_key, pkX, pkY}, nil
}

func GenSessionKey(publicKeyX *big.Int, publicKeyY *big.Int, privateKey *big.Int) (*big.Int, *big.Int) {
	return elliptic.P521().ScalarMult(publicKeyX, publicKeyY, privateKey.Bytes())
}
