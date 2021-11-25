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
	//os.Chdir(path)
	switch entry.Type {
	case 0:
		var n string
		if entry.Name == "" {
			n = "nameless"
		} else {
			n = entry.Name
		}
		log.Printf("Got name=%s", n)
		f, err := os.Open(fmt.Sprintf("%s/%s", path, n))
		defer f.Close()
		if err != nil {
			e, _ := err.(*os.PathError)
			log.Fatal(e)
		}
		f.Write(entry.Data)

	case 1:
		f, err := os.Open(fmt.Sprintf("%s/%s", path, entry.Name))
		defer f.Close()
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

	case 2:
		var n string
		if entry.Name == "" {
			n = "root"
		} else {
			n = entry.Name
		}
		err := os.Mkdir(fmt.Sprintf("%s/%s", path, n), 0755)
		if err != nil {
			log.Fatal(err)
		}
		for _, c := range entry.Children {
			outputEntryToDisk(c, path) // fmt.Sprintf("%s/%s", path, n)
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

	log.Printf("Got: %s", reply.Name)

	common.DisplayDirectory(reply, 0)

	dir, err := os.Getwd()
	if err != nil {
		fmt.Println(err)
	}
	outputEntryToDisk(reply, dir)
}
