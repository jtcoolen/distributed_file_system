package main

import (
	"dfs/common"
	"encoding/hex"
	"fmt"
	"log"
	"net/rpc"
	"os"
)

func main() {
	// Asynchronous call
	hash_str := os.Args[1]
	reply := new(common.Entry)
	client, err := rpc.DialHTTP("tcp", "localhost:9000")
	if err != nil {
		log.Fatal("dialing:", err)
	}
	hash_bytes, err := hex.DecodeString(hash_str)
	if err != nil {
		log.Fatal(err)
	}
	var hash [32]byte
	copy(hash[:], hash_bytes)
	err = client.Call("Node.RetrieveEntry", hash, &reply)
	if err != nil {
		log.Fatal("arith error:", err)
	}
	fmt.Printf("Got: %d", reply.EntryType)
}
