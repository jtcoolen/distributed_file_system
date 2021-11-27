# Start the node
```go run dfs/node```

# Start the RPC client

## List files
```go run dfs/rpc_client ls -path=/ -peer=jch.irif.fr```
```go run dfs/rpc_client ls -path=/documents -peer=jch.irif.fr```

## Download files
### From a hash
```go run dfs/rpc_client download -hash 8dbd2c084064473a16640235662d60083c64806a635ed67a79aa4d0b8a313dae```
### From a path
```go run dfs/rpc_client downloadFromPath -path=/documents -peer=jch.irif.fr```

# TODO:
## High priority
[] export our own tree (reply back to GetDatum(hash) with a Datum(hash)) (Minoo)
[] implement a RPC call UpdateDirectory() to update our own directory (add commands mkdir and create to create new directories and files, respectively) (Minoo)
[] implement NAT Traversal (Minoo & Julien)
[] Implement DH key exchange (Julien)
[] Write report: Usage instructions, Architecture, Features (with logs)
## Low priority
[] Packet Encryption?
[] Pipelining?