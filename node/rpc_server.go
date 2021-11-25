package main

import (
	"io"
	"net/http"
	"net/rpc"
)

func rpcServer(context *Node) {
	rpc.Register(context)
	rpc.HandleHTTP()

	http.HandleFunc("/", func(res http.ResponseWriter, req *http.Request) {
		io.WriteString(res, "RPC server is up")
	})

	http.ListenAndServe(":9000", nil)
}
