package main

import (
	"bufio"
	"flag"
	"fmt"
	"iter"
	"os"
	"strings"

	"go.sia.tech/core/types"
	"go.sia.tech/coreutils/wallet"
)

func printlnf(format string, a ...interface{}) {
	fmt.Fprintf(os.Stdout, format+"\n", a...)
}

func fatalf(format string, a ...interface{}) {
	printlnf(format, a...)
	os.Exit(1)
}

func replacef(format string, a ...interface{}) {
	fmt.Fprintf(os.Stdout, "\r\033[K"+format, a...)
}

func check(context string, start uint64) iter.Seq[uint64] {
	const maxIndex = 1e5
	return func(yield func(uint64) bool) {
		printlnf("Starting Search at index %d...", start)
		printlnf("Press Ctrl+C to stop searching at any time.")
		current := start
		for i := 0; i <= maxIndex; i++ {
			// note: this loop is structured to allow for wrapping when
			// checking high indices that could overflow.
			if current%1000 == 0 {
				replacef("Checking index %d", current)
			}
			if !yield(current) {
				return
			}
			current++
		}

		printlnf(`
%s not found in range %d-%d.
Search will continue, but the probability of finding a match is low.
This %s was likely not derived from the supplied seed.`, strings.ToUpper(context[:1])+context[1:], start, current, context)

		for ; ; current++ {
			if current%1000 == 0 {
				replacef("Checking index %d", current)
			}
			if !yield(current) {
				return
			}
		}
	}
}

func runCheckAddr(start uint64) {
	s := bufio.NewScanner(os.Stdin)
	os.Stdout.WriteString("Enter address: ")
	s.Scan()
	var addr types.Address
	if err := addr.UnmarshalText([]byte(s.Text())); err != nil {
		fatalf("invalid address: %v", err)
	}

	os.Stdout.WriteString("Enter recovery phrase: ")
	s.Scan()
	var seed [32]byte
	if err := wallet.SeedFromPhrase(&seed, s.Text()); err != nil {
		fatalf("invalid seed: %v", err)
	}

	for i := range check("address", start) {
		pk := wallet.KeyFromSeed(&seed, i)
		if types.StandardUnlockHash(pk.PublicKey()) == addr {
			replacef("Standard unlock hash at index %v\n", i)
			return
		} else if types.StandardAddress(pk.PublicKey()) == addr {
			replacef("Standard address at index %v\n", i)
			return
		}
	}
}

func runCheckPubKey(start uint64) {
	s := bufio.NewScanner(os.Stdin)
	os.Stdout.WriteString("Enter public key: ")
	s.Scan()
	var pk types.PublicKey
	if err := pk.UnmarshalText([]byte(s.Text())); err != nil {
		fatalf("invalid public key: %v", err)
	}

	os.Stdout.WriteString("Enter recovery phrase: ")
	s.Scan()
	var seed [32]byte
	if err := wallet.SeedFromPhrase(&seed, s.Text()); err != nil {
		fatalf("invalid seed: %v", err)
	}

	for i := range check("public key", start) {
		if wallet.KeyFromSeed(&seed, i).PublicKey() == pk {
			replacef("Public key found at index %v\n", i)
			return
		}
	}
}

func main() {
	var startIndex uint64
	flag.Uint64Var(&startIndex, "start", 0, "index to start searching from")
	flag.Parse()

	if len(flag.Args()) == 0 {
		runCheckAddr(startIndex)
		return
	}

	cmd := flag.Arg(0)
	switch cmd {
	case "address":
		runCheckAddr(startIndex)
	case "pubkey":
		runCheckPubKey(startIndex)
	default:
		fatalf("Unknown command %q", cmd)
	}
}
