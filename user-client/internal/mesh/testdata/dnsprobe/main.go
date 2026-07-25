// Command dnsprobe is a throwaway helper built and run only by
// mesh_integration_test.go's real-Headscale/real-tailscale CL-F-05 test.
//
// It exists because Tailscale's own local MagicDNS stub resolver
// (100.100.100.100, documented at tailscale.com/kb/1054/dns) is reachable
// ONLY from inside a node that has actually joined a tailnet - not from the
// go test process's own host network namespace. This binary is copied
// ("docker cp") into a real, mesh-joined tailscale/tailscale container and
// run there ("docker exec"), so the net.Resolver.LookupHost call below
// executes inside that container's network namespace, genuinely exercising
// CL-F-05 (MagicDNS resolution), not a stand-in for it.
//
// Living under testdata/ keeps "go build ./...", "go vet ./...", and
// "go test ./..." from ever touching it as part of the ordinary tree (the
// Go toolchain excludes any directory named "testdata" from "./..."
// pattern expansion) - the parent test builds it explicitly by package
// path instead.
package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"time"
)

// magicDNSResolverAddr is Tailscale's own well-known per-node MagicDNS
// stub resolver address - see this file's own package doc comment.
const magicDNSResolverAddr = "100.100.100.100:53"

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: dnsprobe <hostname>")
		os.Exit(2)
	}
	hostname := os.Args[1]

	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, magicDNSResolverAddr)
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	addrs, err := resolver.LookupHost(ctx, hostname)
	if err != nil {
		fmt.Fprintf(os.Stderr, "LookupHost(%q): %v\n", hostname, err)
		os.Exit(1)
	}
	if len(addrs) == 0 {
		fmt.Fprintf(os.Stderr, "LookupHost(%q): no addresses returned\n", hostname)
		os.Exit(1)
	}
	fmt.Println(addrs[0])
}
