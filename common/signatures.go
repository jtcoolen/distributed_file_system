package common

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"math/big"
)

func GenECDSAKeyPair() (*ecdsa.PublicKey, *ecdsa.PrivateKey, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return &privateKey.PublicKey, privateKey, nil
}

func GetFormattedECDSAPublicKey(publicKey *ecdsa.PublicKey) [64]byte {
	formatted := [64]byte{}
	publicKey.X.FillBytes(formatted[:32])
	publicKey.Y.FillBytes(formatted[32:])
	return formatted
}

func SignECDSA(privateKey *ecdsa.PrivateKey, data []byte) ([]byte, error) {
	hashed := sha256.Sum256(data)
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hashed[:])
	if err != nil {
		return nil, err
	}
	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])
	return signature, nil
}

func VerifyECDSASignature(publicKey [64]byte, signature [64]byte, data []byte) bool {
	var r, s big.Int
	var x, y big.Int
	x.SetBytes(publicKey[:32])
	y.SetBytes(publicKey[32:])
	pk := ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     &x,
		Y:     &y,
	}
	pk.X.SetBytes(publicKey[:32])
	pk.Y.SetBytes(publicKey[32:])
	r.SetBytes(signature[:32])
	s.SetBytes(signature[32:])
	hashed := sha256.Sum256(data)
	return ecdsa.Verify(&pk, hashed[:], &r, &s)
}
