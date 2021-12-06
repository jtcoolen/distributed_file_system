package common

import "errors"

var ErrNotFound = errors.New("not found")
var ErrNoPublicKey = errors.New("no public key")
var ErrNoRoot = errors.New("no root")
var ErrWrongKeySize = errors.New("wrong key size")
var ErrWrongHashSize = errors.New("wrong hash size")
var ErrNoSuchType = errors.New("no such type")
var ErrNoAddresses = errors.New("no such address")
var ErrPubKeyOutOfCurve = errors.New("public key out of the curve")
var ErrMakePacket = errors.New("make packet")
