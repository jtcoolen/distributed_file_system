package main

import (
	"crypto/sha256"
	"time"
)

var juliusz = "jch.irif.fr"

var hashLength = sha256.Size
var publicKeyLength = 64
var signatureLength = 64

var helloPeriod time.Duration = 30 * time.Second

var helloType byte = 0
var helloReplyType byte = 128

var publicKeyType byte = 1
var publicKeyReplyType byte = 129

var rootType byte = 2
var rootReplyType byte = 130

var getDatumType byte = 3
var datumType byte = 131
var noDatumType byte = 132

var natTraversalRequestType byte = 133
var natTraversalType byte = 134

var errorType byte = 254
