package main

import (
	"dfs/common"
	"encoding/hex"
	"fmt"
	"log"
	"net/rpc"
	"os"
	"strings"
)

func outputEntryToDisk(entry *common.Entry, path string) {
	switch entry.Type {
	case 0:
		var n string
		if entry.Name == "" {
			n = "nameless"
		} else {
			n = entry.Name
		}
		//n = strings.SplitAfter(n, "")[0]
		s := fmt.Sprintf("%s/%s", path, n)
		log.Printf("Got name=%d", len(n))
		f, err := os.OpenFile(s, os.O_RDWR|os.O_CREATE, 0644)
		if err != nil {
			e, _ := err.(*os.PathError)
			log.Fatal(e)
		}
		//defer f.Close()
		f.Write(entry.Data)

	case 1:
		f, err := os.OpenFile(fmt.Sprintf("%s/%s", path, entry.Name), os.O_RDWR|os.O_CREATE, 0644)
		if err != nil {
			log.Fatal(err)
		}
		defer f.Close()
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
		n = strings.SplitAfter(n, " ")[0]
		log.Print(fmt.Sprintf("Creating dir %s/%s", path, n))
		err := os.Mkdir(fmt.Sprintf("%s/%s", path, n), 0770)
		if err != nil {
			log.Fatal(err)
		}
		for _, c := range entry.Children {
			outputEntryToDisk(c, fmt.Sprintf("%s/%s", path, n))
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

	log.Printf("Got: %d", reply.Type)

	//common.DisplayDirectory(reply, 0)

	dir, err := os.Getwd()
	if err != nil {
		fmt.Println(err)
	}

	/*_, err = os.OpenFile("/home/jco/dfs/root/hello", os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		e, _ := err.(*os.PathError)
		log.Fatal(e)
	}*/

	outputEntryToDisk(reply, dir)
}
