package main

import (
	"dfs/node"
)

func main() {
	// Asynchronous call
	entry := new(node.Entry)
	divCall := client.Go("Arith.Divide", hash, entry, nil)
	replyCall := <-divCall.Done // will be equal to divCall
	// check errors, print, etc.
}
