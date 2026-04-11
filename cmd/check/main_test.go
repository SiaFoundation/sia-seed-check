package main

import (
	"slices"
	"testing"

	"go.sia.tech/core/types"
	"go.sia.tech/coreutils/wallet"
)

const testPhrase = "ramp unfair key hundred flower urban light tuna garden report blade random"

func TestCheckByteCorruption(t *testing.T) {
	tests := []struct {
		name    string
		corrupt func(keySeed []byte)
		expPos  int
		expVal  func(keySeed []byte) byte
	}{
		{
			name:    "single bit flip",
			corrupt: func(keySeed []byte) { keySeed[10] ^= 1 << 5 },
			expPos:  10,
			expVal:  func(keySeed []byte) byte { return keySeed[10] },
		},
		{
			name:    "multi-bit same byte",
			corrupt: func(keySeed []byte) { keySeed[7] ^= 0b10110000 },
			expPos:  7,
			expVal:  func(keySeed []byte) byte { return keySeed[7] },
		},
		{
			name:    "all bits flipped in byte",
			corrupt: func(keySeed []byte) { keySeed[20] ^= 0xFF },
			expPos:  20,
			expVal:  func(keySeed []byte) byte { return keySeed[20] },
		},
		{
			name:    "arbitrary byte replacement",
			corrupt: func(keySeed []byte) { keySeed[5] = 0x42 },
			expPos:  5,
			expVal:  func(keySeed []byte) byte { return keySeed[5] },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var seed [32]byte
			if err := wallet.SeedFromPhrase(&seed, testPhrase); err != nil {
				t.Fatal(err)
			}
			pk := wallet.KeyFromSeed(&seed, 0)
			keySeed := []byte(pk[:32])
			expectedVal := tt.expVal(keySeed)
			original := pk.PublicKey()

			tt.corrupt(keySeed)

			pos, val, ok := checkByteCorruption(0, keySeed, func(pk types.PublicKey) bool {
				return pk == original
			})
			if !ok {
				t.Fatal("expected checkByteCorruption to find corruption")
			}
			if pos != tt.expPos {
				t.Fatalf("expected position %d, got %d", tt.expPos, pos)
			}
			if val != expectedVal {
				t.Fatalf("expected value %d, got %d", expectedVal, val)
			}
		})
	}
}

func TestCheckByteCorruption_Address(t *testing.T) {
	var seed [32]byte
	if err := wallet.SeedFromPhrase(&seed, testPhrase); err != nil {
		t.Fatal(err)
	}
	pk := wallet.KeyFromSeed(&seed, 0)
	keySeed := []byte(pk[:32])
	expectedVal := keySeed[5]
	addr := types.StandardAddress(pk.PublicKey())

	keySeed[5] = 0x42

	pos, val, ok := checkByteCorruption(0, keySeed, func(pk types.PublicKey) bool {
		return types.StandardUnlockHash(pk) == addr || types.StandardAddress(pk) == addr
	})
	if !ok {
		t.Fatal("expected checkByteCorruption to find corruption via address")
	}
	if pos != 5 {
		t.Fatalf("expected position 5, got %d", pos)
	}
	if val != expectedVal {
		t.Fatalf("expected value %d, got %d", expectedVal, val)
	}
}

func TestCheckCrossByteBitFlips(t *testing.T) {
	tests := []struct {
		name     string
		corrupt  func(keySeed []byte)
		maxFlips int
		expBits  []int
	}{
		{
			name: "two bytes",
			corrupt: func(keySeed []byte) {
				keySeed[2] ^= 1 << 3
				keySeed[15] ^= 1 << 6
			},
			maxFlips: 2,
			expBits:  []int{2*8 + 3, 15*8 + 6},
		},
		{
			name: "three bytes",
			corrupt: func(keySeed []byte) {
				keySeed[0] ^= 1 << 1
				keySeed[8] ^= 1 << 4
				keySeed[31] ^= 1 << 7
			},
			maxFlips: 3,
			expBits:  []int{0*8 + 1, 8*8 + 4, 31*8 + 7},
		},
		{
			name: "not enough flips",
			corrupt: func(keySeed []byte) {
				keySeed[0] ^= 1 << 0
				keySeed[10] ^= 1 << 3
				keySeed[20] ^= 1 << 5
			},
			maxFlips: 2,
			expBits:  nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var seed [32]byte
			if err := wallet.SeedFromPhrase(&seed, testPhrase); err != nil {
				t.Fatal(err)
			}
			pk := wallet.KeyFromSeed(&seed, 0)
			keySeed := []byte(pk[:32])
			original := pk.PublicKey()

			tt.corrupt(keySeed)

			result := checkCrossByteBitFlips(keySeed, func(pk types.PublicKey) bool {
				return pk == original
			}, tt.maxFlips)

			if tt.expBits == nil {
				if result != nil {
					t.Fatalf("expected no match, got %v", result)
				}
				return
			}
			if result == nil {
				t.Fatal("expected match, got nil")
			}
			if len(result) != len(tt.expBits) {
				t.Fatalf("expected %d flipped bits, got %d", len(tt.expBits), len(result))
			}
			slices.Sort(result)
			if !slices.Equal(result, tt.expBits) {
				t.Fatalf("expected bit positions %v, got %v", tt.expBits, result)
			}
		})
	}
}
