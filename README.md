# sia-addr-check

A command-line tool that checks whether a Sia address was derived from a given
recovery phrase. It searches through derivation indices to find which index
(if any) produced the address.

Only the standard derivation is checked. Multi-sig or other custom conditions cannot be checked.

## Build

Requires Go 1.25+.

```sh
go build -o sia-addr-check ./cmd/check
```

## Usage

```sh
./sia-addr-check
```

The program prompts for two inputs:

1. A Sia address
2. A recovery phrase (seed)

It then searches indices 0 through 100,000, printing progress every 1,000
indices. If a match is found, it prints the derivation type and index, then
exits. If no match is found in the first 100,000 indices, the search continues
indefinitely. Press `Ctrl+C` to stop at any time.
