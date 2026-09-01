// Package main implements offline verification of a Falden evidence pack.
//
// The whole program is three files and the Go standard library. That is
// deliberate. This is code meant to be read by someone deciding whether to
// trust a document produced by a party they do not yet trust, and a verifier
// nobody can read is not a verifier, it is a second thing to take on faith.
//
// There is no network access anywhere in this repository. There is no
// configuration, no telemetry, no update check, and no way to reach Falden. If
// you disconnect the machine, everything here still works.
package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// The two domain strings. Every byte matters, including the newlines.
//
// A domain prefix stops a signature made for one purpose being presented as a
// signature for another. Without distinct prefixes, a signature over a chain
// root could be replayed as a signature over a pack digest whenever the two hex
// strings happened to coincide.
const (
	packSignDomain = "falden-pack-ed25519-v1"
	chainDomain    = "falden-chain-v1"
)

// zeroPrev is the predecessor hash of the first link: 64 zeros.
const zeroPrev = "0000000000000000000000000000000000000000000000000000000000000000"

var (
	errSealFailed    = errors.New("the pack does not match its signature")
	errChainFailed   = errors.New("the chain does not recompute from its own object ids")
	errKeyMismatch   = errors.New("the supplied key is not the key named in the pack")
	errEmptyPack     = errors.New("the pack is empty")
	errBadSignature  = errors.New("the signature is not 64 bytes")
	errBadPublicKey  = errors.New("the key is not an Ed25519 public key")
	errNoChainInPack = errors.New("the pack contains no chain")
)

// Pack is the minimum of the pack this program needs to read. A pack contains
// a great deal more, and none of the rest is required to check either
// guarantee, which is itself worth noticing: verification does not depend on
// understanding the measurements.
type Pack struct {
	Kind      string `json:"kind"`
	Version   int    `json:"version"`
	Forge     string `json:"forge"`
	Chain     Chain  `json:"chain"`
	VerifyKey string `json:"verify_key_fingerprint"`
}

// Chain is the append-only hash chain over git commit object identifiers.
type Chain struct {
	Links []Link `json:"links"`
	Root  string `json:"root"`
}

// Link is one entry. Prev is the previous link's hash, which is what makes the
// structure a chain rather than a list: changing any earlier object id changes
// every hash after it, and therefore changes the root.
type Link struct {
	Seq      uint64 `json:"seq"`
	ObjectID string `json:"object_id"`
	Prev     string `json:"prev"`
	Hash     string `json:"hash"`
}

// Result is what verification produced. Every field is reported, including on
// failure, because "which check failed" is the useful part.
type Result struct {
	Digest       string
	BytesCovered int
	ChainRoot    string
	CommitCount  int
	KeyID        string
	SealOK       bool
	ChainOK      bool
	KeyMatchesID bool
}

// PackDigest is the SHA-256 of the pack's exact bytes, lowercase hex. It is
// the same value as:
//
//	openssl dgst -sha256 -r pack.json
func PackDigest(packBytes []byte) string {
	sum := sha256.Sum256(packBytes)
	return hex.EncodeToString(sum[:])
}

// PackSignedMessage is the exact byte sequence the signature covers. The shell
// equivalent is one printf:
//
//	printf 'falden-pack-ed25519-v1\n%s\n' "$digest"
func PackSignedMessage(digestHex string) []byte {
	return []byte(packSignDomain + "\n" + digestHex + "\n")
}

// linkHash recomputes one chain link. The preimage is the domain, the sequence
// number in decimal, the object id, and the previous hash, each followed by a
// newline. Length-delimiting by newline is safe here only because none of the
// four fields can contain a newline: the domain is a constant, the sequence is
// digits, and both hashes and git object ids are hex.
func linkHash(seq uint64, objectID, prev string) string {
	var b strings.Builder
	b.WriteString(chainDomain)
	b.WriteByte('\n')
	b.WriteString(strconv.FormatUint(seq, 10))
	b.WriteByte('\n')
	b.WriteString(objectID)
	b.WriteByte('\n')
	b.WriteString(prev)
	b.WriteByte('\n')
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:])
}

// ParsePublicKey reads a PEM-encoded Ed25519 public key.
func ParsePublicKey(pemBytes []byte) (ed25519.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("no PEM block found in the key file")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse key: %w", err)
	}
	pub, ok := parsed.(ed25519.PublicKey)
	if !ok {
		return nil, errBadPublicKey
	}
	return pub, nil
}

// KeyFingerprint is the SHA-256 of the DER-encoded public key, lowercase hex.
// The pack names the key it was signed with using this value, which lets a
// reader tell "you gave me the wrong key" apart from "this pack was altered".
// Those two failures look identical otherwise, and confusing them wastes an
// afternoon.
func KeyFingerprint(pub ed25519.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:]), nil
}

// VerifySeal checks that the key vouches for every byte of the pack.
func VerifySeal(packBytes, sig []byte, pub ed25519.PublicKey) error {
	if len(packBytes) == 0 {
		return errEmptyPack
	}
	if len(sig) != ed25519.SignatureSize {
		return errBadSignature
	}
	if len(pub) != ed25519.PublicKeySize {
		return errBadPublicKey
	}
	if !ed25519.Verify(pub, PackSignedMessage(PackDigest(packBytes)), sig) {
		return errSealFailed
	}
	return nil
}

// VerifyChain recomputes the chain from its own object ids and checks that it
// arrives at the stated root.
//
// This is a different guarantee from the seal, and the difference is the point.
// The seal says Falden vouches for this file. The chain says the commit
// population inside it is internally consistent and can be re-derived from a
// clone of the repository, which is evidence that does not depend on trusting
// Falden at all.
func VerifyChain(c Chain) error {
	if len(c.Links) == 0 {
		return errNoChainInPack
	}
	prev := zeroPrev
	for i, l := range c.Links {
		wantSeq := uint64(i + 1)
		if l.Seq != wantSeq {
			return fmt.Errorf("%w: link %d states sequence %d", errChainFailed, i+1, l.Seq)
		}
		if l.Prev != prev {
			return fmt.Errorf("%w: link %d does not follow its predecessor", errChainFailed, i+1)
		}
		h := linkHash(l.Seq, l.ObjectID, l.Prev)
		if h != l.Hash {
			return fmt.Errorf("%w: link %d hash does not recompute", errChainFailed, i+1)
		}
		prev = h
	}
	if prev != c.Root {
		return fmt.Errorf("%w: recomputed root %s, pack states %s", errChainFailed, prev, c.Root)
	}
	return nil
}

// Verify runs both checks and reports what it found.
//
// It returns an error if either check fails, and a Result either way, so a
// caller can print the digest and the chain root even when verification failed.
// A reader looking at a failure usually wants to know which pack it was.
func Verify(packBytes, sig []byte, pub ed25519.PublicKey) (Result, error) {
	res := Result{
		Digest:       PackDigest(packBytes),
		BytesCovered: len(packBytes),
	}

	var p Pack
	if err := json.Unmarshal(packBytes, &p); err != nil {
		return res, fmt.Errorf("the pack is not valid JSON: %w", err)
	}
	res.ChainRoot = p.Chain.Root
	res.CommitCount = len(p.Chain.Links)
	res.KeyID = p.VerifyKey

	if fp, err := KeyFingerprint(pub); err == nil && p.VerifyKey != "" {
		res.KeyMatchesID = fp == p.VerifyKey
		if !res.KeyMatchesID {
			return res, fmt.Errorf("%w: this key is %s, the pack names %s",
				errKeyMismatch, fp[:16]+"...", p.VerifyKey[:16]+"...")
		}
	}

	if err := VerifySeal(packBytes, sig, pub); err != nil {
		return res, err
	}
	res.SealOK = true

	if err := VerifyChain(p.Chain); err != nil {
		return res, err
	}
	res.ChainOK = true

	return res, nil
}
