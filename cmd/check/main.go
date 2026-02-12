package main

import (
	"bufio"
	"fmt"
	"os"

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

func matchingAddr(addr types.Address, seed *[32]byte, i uint64) bool {
	pk := wallet.KeyFromSeed(seed, i)
	if types.StandardUnlockHash(pk.PublicKey()) == addr {
		printlnf("\rStandard unlock hash at index %v", i)
		return true
	} else if types.StandardAddress(pk.PublicKey()) == addr {
		printlnf("\rStandard address at index %v", i)
		return true
	}
	return false
}

func main() {
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

	printlnf("Starting Search...")
	printlnf("Press Ctrl+C to stop searching at any time.")
	for i := uint64(0); i <= 1e5; i++ {
		if i%1000 == 0 {
			fmt.Fprintf(os.Stdout, "\rchecking index %d", i)
		}
		if matchingAddr(addr, &seed, i) {
			return
		}
	}

	printlnf(`Address not found in first 100000 indices.
Search will continue, but the probability of finding a match is low.
This address was likely not derived from the supplied seed.`)

	for i := uint64(1e5); ; i++ {
		if i%1000 == 0 {
			fmt.Fprintf(os.Stdout, "\rchecking index %d", i)
		}
		if matchingAddr(addr, &seed, i) {
			return
		}
	}
}
