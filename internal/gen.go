package solstice

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux packet packet.ebpf.c -o ./internal
