package main

import (
	"dfs/common"
	"encoding/hex"
	"fmt"
	"log"
	"net/rpc"
	"os"
)

func outputEntryToDisk(entry *common.Entry, path string) {
	switch entry.Type {
	case 0:
		f, err := os.Create(fmt.Sprintf("%s/%s", path, entry.Name))
		if err != nil {
			log.Fatal(err)
		}
		f.Write(entry.Data)
		f.Close()
	case 1:
		f, err := os.Create(fmt.Sprintf("%s/%s", path, entry.Name))
		if err != nil {
			log.Fatal(err)
		}
		for _, c := range entry.Children {
			switch c.Type {
			case 1:
				for _, cc := range c.Children {
					f.Write(cc.Data)
				}
			default:
				f.Write(c.Data)
			}
		}
		f.Close()

	case 2:
		err := os.Mkdir(fmt.Sprintf("%s/%s", path, entry.Name), 0755)
		if err != nil {
			log.Fatal(err)
		}
		for _, c := range entry.Children {
			outputEntryToDisk(c, fmt.Sprintf("%s/%s", path, entry.Name))
		}
	}
}

func main() {
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

	fmt.Printf("Got: %d", reply.Type)

	dir, err := os.Getwd()
	if err != nil {
		fmt.Println(err)
	}
	outputEntryToDisk(reply, dir)
}
