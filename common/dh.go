package common

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"log"
	"math/big"
)

type ECDHKeyPair struct {
	PrivateKey []byte
	PublicKeyX *big.Int
	PublicKeyY *big.Int
}

func GenKeyPair() (*ECDHKeyPair, error) {
	/*max := big.NewInt(0)
	max.Sub(elliptic.P521().Params().N, big.NewInt(1))
	privateKey, err := rand.Int(rand.Reader, max)
	if err != nil {
		return nil, err
	}
	privateKey.Add(privateKey, big.NewInt(1))

	pkX, pkY := elliptic.P521().ScalarMult(
		elliptic.P521().Params().Gx,
		elliptic.P521().Params().Gy,
		privateKey.Bytes())*/

	privateKey, pkX, pkY, err := elliptic.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return &ECDHKeyPair{PrivateKey: privateKey, PublicKeyX: pkX, PublicKeyY: pkY}, nil
}

func GetFormattedECDHKey(publicKeyX *big.Int, publicKeyY *big.Int) [2 * 66]byte {
	formatted := [2 * 66]byte{}
	publicKeyX.FillBytes(formatted[:66])
	publicKeyY.FillBytes(formatted[66:])
	return formatted
}

func GenSessionKey(publicKey [2 * 66]byte, privateKey []byte) ([sha256.Size]byte, error) {
	var x, y big.Int
	formatted := [2 * 66]byte{}

	x.SetBytes(publicKey[:66])
	y.SetBytes(publicKey[66:])

	if !elliptic.P521().IsOnCurve(&x, &y) {
		log.Printf("POINT NOT ON CURVE")
		return sha256.Sum256(formatted[:]), ErrPubKeyOutOfCurve
	}

	mx, my := elliptic.P521().ScalarMult(&x, &y, privateKey)

	mx.FillBytes(formatted[:66])
	my.FillBytes(formatted[66:])

	log.Print("GOOD POINT")

	return sha256.Sum256(formatted[:]), nil
}
