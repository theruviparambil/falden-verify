package main

import (
	"flag"
	"fmt"
	"os"
)

const usage = `falden-verify: check a Falden evidence pack, offline.

usage:
  falden-verify -key falden.pub [-sig pack.sig] pack.json

flags:
  -key     Ed25519 public key, PEM. Published by Falden.
  -sig     detached signature. Defaults to the pack path with .sig appended.
  -quiet   print nothing. Exit 0 if the pack verifies, 1 if it does not.

It checks two independent things:

  1. The seal. That the key vouches for every byte of the pack, so nothing in
     it has changed since it was signed: not the counts, not the rows, not the
     definitions, not the window.

  2. The chain. That the commit population recomputes from its own object
     identifiers, so you can re-derive it from your own clone without trusting
     Falden or this program.

You do not have to run this. Every step is reproducible with stock openssl:

  digest=$(openssl dgst -sha256 -r pack.json | cut -d' ' -f1)
  printf 'falden-pack-ed25519-v1\n%s\n' "$digest" > message.bin
  openssl pkeyutl -verify -pubin -inkey falden.pub -rawin -in message.bin -sigfile pack.sig

If openssl and this program ever disagree, this program is wrong.

No network access. Nothing contacts Falden.
`

func main() {
	keyPath := flag.String("key", "", "path to the Ed25519 public key, PEM")
	sigPath := flag.String("sig", "", "path to the detached signature")
	quiet := flag.Bool("quiet", false, "print nothing, exit 0 on success")
	flag.Usage = func() { fmt.Fprintf(os.Stderr, "%s", usage) }
	flag.Parse()

	if *keyPath == "" || flag.NArg() != 1 {
		flag.Usage()
		os.Exit(2)
	}
	packPath := flag.Arg(0)
	if *sigPath == "" {
		*sigPath = packPath + ".sig"
	}

	keyBytes, err := os.ReadFile(*keyPath)
	if err != nil {
		die(*quiet, "key: %v", err)
	}
	pub, err := ParsePublicKey(keyBytes)
	if err != nil {
		die(*quiet, "key: %v", err)
	}
	packBytes, err := os.ReadFile(packPath)
	if err != nil {
		die(*quiet, "pack: %v", err)
	}
	sig, err := os.ReadFile(*sigPath)
	if err != nil {
		die(*quiet, "signature: %v\n  a pack is sealed by a detached signature stored beside it", err)
	}

	res, verifyErr := Verify(packBytes, sig, pub)

	if verifyErr != nil {
		if *quiet {
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "FAILED: %v\n\n", verifyErr)
		fmt.Fprintf(os.Stderr, "  pack      %s\n", packPath)
		fmt.Fprintf(os.Stderr, "  digest    %s\n", res.Digest)
		if res.ChainRoot != "" {
			fmt.Fprintf(os.Stderr, "  chain     %s\n", res.ChainRoot)
		}
		fmt.Fprintf(os.Stderr, "\n")
		fmt.Fprintf(os.Stderr, "A failure here does not tell you whether the file was altered\n")
		fmt.Fprintf(os.Stderr, "deliberately, altered accidentally, or paired with the wrong\n")
		fmt.Fprintf(os.Stderr, "signature. It tells you the document in front of you is not the\n")
		fmt.Fprintf(os.Stderr, "document that was sealed. Do not assume the benign explanation.\n")
		os.Exit(1)
	}

	if *quiet {
		return
	}
	fmt.Printf("OK\n")
	fmt.Printf("  pack             %s\n", packPath)
	fmt.Printf("  digest           %s\n", res.Digest)
	fmt.Printf("  bytes covered    %d   (the whole file)\n", res.BytesCovered)
	fmt.Printf("  chain root       %s\n", res.ChainRoot)
	fmt.Printf("  commit objects   %d, recomputed and matching\n", res.CommitCount)
	if res.KeyID != "" {
		fmt.Printf("  key fingerprint  %s\n", res.KeyID)
	}
	fmt.Printf("\n")
	fmt.Printf("This confirms the pack was produced by the holder of the private key\n")
	fmt.Printf("matching %s and has not been altered since.\n", *keyPath)
	fmt.Printf("\n")
	fmt.Printf("It says nothing about whether the measurements are correct, whether the\n")
	fmt.Printf("collection was complete, or whether any control is deficient. Falden is\n")
	fmt.Printf("not the attestor and issues no opinion. Those judgements are yours.\n")
}

func die(quiet bool, format string, a ...any) {
	if !quiet {
		fmt.Fprintf(os.Stderr, "falden-verify: "+format+"\n", a...)
	}
	os.Exit(1)
}
