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

func printlnf(format string, a ...any) {
	fmt.Fprintf(os.Stdout, format+"\n", a...)
}

func fatalf(format string, a ...any) {
	printlnf(format, a...)
	os.Exit(1)
}

func replacef(format string, a ...any) {
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

func checkByteCorruption(index uint64, keySeed []byte, match func(types.PublicKey) bool) (pos int, val byte, ok bool) {
	for i := range keySeed {
		replacef("Checking index %d, byte %d/%d", index, i, len(keySeed))
		orig := keySeed[i]
		for j := range 256 {
			keySeed[i] = byte(j)
			if match(types.NewPrivateKeyFromSeed(keySeed).PublicKey()) {
				return i, byte(j), true
			}
		}
		keySeed[i] = orig
	}
	return 0, 0, false
}

func checkCrossByteBitFlips(keySeed []byte, match func(types.PublicKey) bool, maxFlips int) []int {
	for n := 2; n <= maxFlips; n++ {
		if result := checkCrossByteBitFlipsDepth(keySeed, match, n, 0, nil); result != nil {
			return result
		}
	}
	return nil
}

func checkCrossByteBitFlipsDepth(keySeed []byte, match func(types.PublicKey) bool, depth, startBit int, flipped []int) []int {
	if match(types.NewPrivateKeyFromSeed(keySeed).PublicKey()) {
		return flipped
	}
	if depth == 0 {
		return nil
	}
	for bit := startBit; bit < len(keySeed)*8; bit++ {
		// skip combinations within the same byte — already covered by checkByteCorruption
		if len(flipped) > 0 && bit/8 == flipped[len(flipped)-1]/8 {
			continue
		}
		keySeed[bit/8] ^= 1 << (bit % 8)
		if result := checkCrossByteBitFlipsDepth(keySeed, match, depth-1, bit+1, append(flipped, bit)); result != nil {
			return result
		}
		keySeed[bit/8] ^= 1 << (bit % 8)
	}
	return nil
}

func runCheckAddr(start uint64, maxFlips int) {
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

		if maxFlips > 0 {
			keySeed := make([]byte, 32)
			copy(keySeed, pk[:32])
			matchAddr := func(pk types.PublicKey) bool {
				return types.StandardUnlockHash(pk) == addr || types.StandardAddress(pk) == addr
			}
			if pos, val, ok := checkByteCorruption(i, keySeed, matchAddr); ok {
				replacef("Address matches index %v with byte %d changed to %d\n", i, pos, val)
				return
			}
			if result := checkCrossByteBitFlips(keySeed, matchAddr, maxFlips); result != nil {
				replacef("Address matches index %v with cross-byte bit flips at positions: %v\n", i, result)
				return
			}
		}
	}
}

func runCheckPubKey(start uint64, maxFlips int) {
	s := bufio.NewScanner(os.Stdin)
	os.Stdout.WriteString("Enter public key: ")
	s.Scan()
	var targetPK types.PublicKey
	if err := targetPK.UnmarshalText([]byte(s.Text())); err != nil {
		fatalf("invalid public key: %v", err)
	}

	os.Stdout.WriteString("Enter recovery phrase: ")
	s.Scan()
	var seed [32]byte
	if err := wallet.SeedFromPhrase(&seed, s.Text()); err != nil {
		fatalf("invalid seed: %v", err)
	}

	for i := range check("public key", start) {
		derived := wallet.KeyFromSeed(&seed, i)
		if derived.PublicKey() == targetPK {
			replacef("Public key found at index %v\n", i)
			return
		}

		if maxFlips > 0 {
			keySeed := make([]byte, 32)
			copy(keySeed, derived[:32])
			matchPK := func(pk types.PublicKey) bool {
				return pk == targetPK
			}
			if pos, val, ok := checkByteCorruption(i, keySeed, matchPK); ok {
				replacef("Public key matches index %v with byte %d changed to %d\n", i, pos, val)
				return
			}
			if result := checkCrossByteBitFlips(keySeed, matchPK, maxFlips); result != nil {
				replacef("Public key matches index %v with cross-byte bit flips at positions: %v\n", i, result)
				return
			}
		}
	}
}

func main() {
	var startIndex uint64
	var maxFlips int
	flag.Uint64Var(&startIndex, "start", 0, "index to start searching from")
	flag.IntVar(&maxFlips, "max-flips", 3, "maximum number of bit flips to match for check")
	flag.Parse()

	if len(flag.Args()) == 0 {
		runCheckAddr(startIndex, maxFlips)
		return
	}

	cmd := flag.Arg(0)
	switch cmd {
	case "address":
		runCheckAddr(startIndex, maxFlips)
	case "pubkey":
		runCheckPubKey(startIndex, maxFlips)
	default:
		fatalf("Unknown command %q", cmd)
	}
}
