package common

import (
	"crypto/sha256"
	"time"
)

const Juliusz = "jch.irif.fr"

const HashLength = sha256.Size
const PublicKeyLength = 64
const SignatureLength = 64

const HelloPeriod time.Duration = 30 * time.Second

const HelloType byte = 0
const HelloReplyType byte = 128

const PublicKeyType byte = 1
const PublicKeyReplyType byte = 129

const RootType byte = 2
const RootReplyType byte = 130

const GetDatumType byte = 3
const DatumType byte = 131
const NoDatumType byte = 132

const NatTraversalRequestType byte = 133
const NatTraversalType byte = 134

const ErrorType byte = 254

const DHRequest = 64 + 4
const DHKey = 192 + 4
