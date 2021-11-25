package common

import (
	"io"
	"net/http"
	"net/rpc"
)

func RpcServer(context *Node) {
	rpc.Register(context)
	rpc.HandleHTTP()

	http.HandleFunc("/", func(res http.ResponseWriter, req *http.Request) {
		io.WriteString(res, "RPC server is up")
	})

	http.ListenAndServe(":9000", nil)
}
