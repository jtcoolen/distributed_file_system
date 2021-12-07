package main

import (
	"dfs/common"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net/rpc"
	"os"
	"strings"
)

func outputEntryToDisk(entry *common.Entry, path string, f *os.File) {
	switch entry.Type {
	case 0:
		if f != nil {
			f.Write(entry.Data)
		} else {
			var n string
			if entry.Name == "" {
				n = "nameless"
			} else {
				n = entry.Name
			}
			s := fmt.Sprintf("%s/%s", path, n)
			f, err := os.OpenFile(s, os.O_RDWR|os.O_CREATE, 0644)
			if err != nil {
				e, _ := err.(*os.PathError)
				log.Fatal(e)
			}
			defer f.Close()
			f.Write(entry.Data)
		}

	case 1:
		if f == nil {
			fname := fmt.Sprintf("%s/%s", path, entry.Name)
			f, err := os.OpenFile(fname, os.O_RDWR|os.O_CREATE, 0644)
			if err != nil {
				log.Fatal(err)
			}
			defer f.Close()
			for _, c := range entry.Children {
				switch c.Type {
				case 0:
					outputEntryToDisk(c, fname, f)
				case 1:
					outputEntryToDisk(c, fname, f)
				default:
					log.Fatalf("Unexpected type %d", c.Type)
					//f.Write(c.Data)
				}
			}
		} else {
			for _, c := range entry.Children {
				switch c.Type {
				case 0:
					outputEntryToDisk(c, path, f)
				case 1:
					outputEntryToDisk(c, path, f)
				default:
					log.Fatalf("Unexpected type %d", c.Type)
					//f.Write(c.Data)
				}
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
			outputEntryToDisk(c, fmt.Sprintf("%s/%s", path, n), nil)
		}
	}
}

func main() {
	DownloadCmd := flag.NewFlagSet("download", flag.ExitOnError)
	hash_str := DownloadCmd.String("hash", "", "hash")
	peerDownload := DownloadCmd.String("peer", "", "peer")

	DownloadFromPathCmd := flag.NewFlagSet("downloadFromPath", flag.ExitOnError)
	path := DownloadFromPathCmd.String("path", "", "path")
	peer := DownloadFromPathCmd.String("peer", "", "peer")

	PrintDirCmd := flag.NewFlagSet("ls", flag.ExitOnError)
	path1 := PrintDirCmd.String("path", "", "path")
	peer1 := PrintDirCmd.String("peer", "", "peer")

	ContactNodeCmd := flag.NewFlagSet("contactNode", flag.ExitOnError)
	peer2 := ContactNodeCmd.String("peer", "", "peer")

	GetPeerRootCmd := flag.NewFlagSet("getPeerRoot", flag.ExitOnError)
	peer3 := GetPeerRootCmd.String("peer", "", "peer")

	SendDHKeyRequestCmd := flag.NewFlagSet("sendDHKeyRequest", flag.ExitOnError)
	peerSendDHKeyRequest := SendDHKeyRequestCmd.String("peer", "", "peer")

	//GetPeersCmd := flag.NewFlagSet("peers", flag.ExitOnError)

	if len(os.Args) < 2 {
		fmt.Println("expected 'download' or 'peers' subcommands")
		os.Exit(1)
	}

	switch os.Args[1] {
	case "contactNode":
		ContactNodeCmd.Parse(os.Args[2:])
		reply := new(string)

		client, err := rpc.DialHTTP("tcp", "localhost:9000")
		if err != nil {
			log.Fatal("dialing:", err)
		}
		err = client.Call("Node.ContactNode", *peer2, &reply)
		if err != nil {
			log.Fatal("Node.ContactNode error:", err)
		}

	case "download":
		DownloadCmd.Parse(os.Args[2:])
		reply := new(common.Entry)

		client, err := rpc.DialHTTP("tcp", "localhost:9000")
		if err != nil {
			log.Fatal("dialing:", err)
		}

		hash_bytes, err := hex.DecodeString(*hash_str)
		if err != nil {
			log.Fatal(err)
		}

		var hash [32]byte
		copy(hash[:], hash_bytes)
		log.Printf("hash %x", hash)

		err = client.Call("Node.RetrieveEntry", common.RetrieveEntryArgs{Peer: *peerDownload, Hash: hash}, &reply)
		if err != nil {
			log.Fatal("Node.RetrieveEntry error:", err)
		}

		dir, err := os.Getwd()
		if err != nil {
			log.Fatal(err)
		}

		outputEntryToDisk(reply, dir, nil)

	case "downloadFromPath":
		DownloadFromPathCmd.Parse(os.Args[2:])
		reply := new(common.Entry)
		//log.Print(strings.Split("documents/README.text", "/"))

		log.Print(*path, *peer)
		log.Print(len(strings.Split(*path, "/")), strings.Split(*path, "/"))
		client, err := rpc.DialHTTP("tcp", "localhost:9000")
		if err != nil {
			log.Fatal("dialing:", err)
		}
		err = client.Call("Node.RetrieveEntryByPath", common.RetrieveEntryByPathArgs{Peer: *peer, Path: *path}, &reply)
		if err != nil {
			log.Fatal("Node.RetrieveEntryByPath error:", err)
		}

		dir, err := os.Getwd()
		if err != nil {
			log.Fatal(err)
		}

		log.Print(reply.Hash)
		//common.DisplayDirectory(reply, 0)
		outputEntryToDisk(reply, dir, nil)

	case "ls":
		PrintDirCmd.Parse(os.Args[2:])
		reply := new(string)

		client, err := rpc.DialHTTP("tcp", "localhost:9000")
		if err != nil {
			log.Fatal("dialing:", err)
		}
		err = client.Call("Node.DisplayDirectoryPath", common.RetrieveEntryByPathArgs{Peer: *peer1, Path: *path1}, &reply)
		if err != nil {
			log.Fatal("Node.DisplayDirectoryPath error:", err)
		}

		fmt.Print(*reply)

	case "peers":
		peers, err := common.GetPeers()
		if err != nil {
			log.Fatal(err)
		}
		for i, p := range peers {
			fmt.Printf("%d: %s\n", i, string(p))
		}

	case "getPeerRoot":
		GetPeerRootCmd.Parse(os.Args[2:])
		reply := new(string)

		client, err := rpc.DialHTTP("tcp", "localhost:9000")
		if err != nil {
			log.Fatal("dialing:", err)
		}
		err = client.Call("Node.GetPeerRootHash", *peer3, &reply)
		if err != nil {
			log.Fatal("Node.GetPeerRootHash error:", err)
		}

		fmt.Println(*reply)

	case "sendDHKeyRequest":
		SendDHKeyRequestCmd.Parse(os.Args[2:])
		client, err := rpc.DialHTTP("tcp", "localhost:9000")
		if err != nil {
			log.Fatal("dialing:", err)
		}
		err = client.Call("Node.SendDHKeyRequest", peerSendDHKeyRequest, nil)
		if err != nil {
			log.Fatal("Node.SendDHKeyRequest error:", err)
		}

	default:
		fmt.Println("expected 'download' or 'peers' subcommands")
		os.Exit(1)
	}
}
