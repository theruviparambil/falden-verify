package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// The fixture is a real pack, signed by a real key whose private half was
// destroyed after generating it. Nothing in this repository can produce a new
// signature, which is the correct capability for a verifier to have.
const (
	fixturePack = "testdata/sample-pack.json"
	fixtureSig  = "testdata/sample-pack.json.sig"
	fixtureKey  = "testdata/sample.pub"
)

func load(t *testing.T) (packBytes, sig []byte, pub ed25519.PublicKey) {
	t.Helper()
	packBytes, err := os.ReadFile(fixturePack)
	if err != nil {
		t.Fatalf("fixture pack: %v", err)
	}
	sig, err = os.ReadFile(fixtureSig)
	if err != nil {
		t.Fatalf("fixture signature: %v", err)
	}
	keyPEM, err := os.ReadFile(fixtureKey)
	if err != nil {
		t.Fatalf("fixture key: %v", err)
	}
	pub, err = ParsePublicKey(keyPEM)
	if err != nil {
		t.Fatalf("parse key: %v", err)
	}
	return packBytes, sig, pub
}

// The exact bytes under signature are an interop contract with every auditor's
// shell. If this test fails, every pack ever issued has stopped verifying.
func TestSignedMessageLayout(t *testing.T) {
	got := PackSignedMessage("abc123")
	want := []byte("falden-pack-ed25519-v1\nabc123\n")
	if !bytes.Equal(got, want) {
		t.Fatalf("signed message layout changed\n got: %q\nwant: %q", got, want)
	}
}

func TestFixtureVerifies(t *testing.T) {
	packBytes, sig, pub := load(t)
	res, err := Verify(packBytes, sig, pub)
	if err != nil {
		t.Fatalf("the genuine fixture must verify, got %v", err)
	}
	if !res.SealOK || !res.ChainOK || !res.KeyMatchesID {
		t.Fatalf("all three checks must pass, got %+v", res)
	}
	if res.CommitCount != 5 {
		t.Fatalf("expected 5 commit objects, got %d", res.CommitCount)
	}
}

// The regression this whole repository exists to make checkable: editing a
// measurement must break the seal. Before the pack was sealed as a whole, this
// edit left the signature verifying, because the signature covered only the
// chain root and a chain root is a digest of commit ids.
func TestEditingAFindingBreaksTheSeal(t *testing.T) {
	packBytes, sig, pub := load(t)

	var doc map[string]any
	if err := json.Unmarshal(packBytes, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	cov := doc["coverage"].(map[string]any)
	cov["large_machine_attributed_without_independent_approval"] = 0
	tampered, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	if _, err := Verify(tampered, sig, pub); err == nil {
		t.Fatal("a pack with an edited finding verified; the seal does not cover the findings")
	}
}

// Byte-level paranoia. A seal that misses whitespace misses everything.
func TestAnyByteEditBreaksTheSeal(t *testing.T) {
	packBytes, sig, pub := load(t)
	for _, at := range []int{0, len(packBytes) / 3, len(packBytes) / 2, len(packBytes) - 2} {
		edited := append([]byte(nil), packBytes...)
		edited[at] ^= 0x20
		if err := VerifySeal(edited, sig, pub); err == nil {
			t.Fatalf("edit at byte %d verified", at)
		}
	}
	if err := VerifySeal(append(append([]byte(nil), packBytes...), '\n'), sig, pub); err == nil {
		t.Fatal("an appended newline verified")
	}
}

// The chain is checked independently of the seal, so a pack whose seal is
// intact but whose chain does not recompute must still fail. That combination
// should be impossible in practice, which is exactly why it is worth asserting.
func TestChainIsCheckedIndependently(t *testing.T) {
	packBytes, _, _ := load(t)
	var p Pack
	if err := json.Unmarshal(packBytes, &p); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if err := VerifyChain(p.Chain); err != nil {
		t.Fatalf("the genuine chain must recompute, got %v", err)
	}

	cases := map[string]func(c *Chain){
		"object id changed": func(c *Chain) { c.Links[2].ObjectID = strings.Repeat("a", 40) },
		"link hash changed": func(c *Chain) { c.Links[1].Hash = strings.Repeat("b", 64) },
		"root changed":      func(c *Chain) { c.Root = strings.Repeat("c", 64) },
		"sequence changed":  func(c *Chain) { c.Links[3].Seq = 99 },
		"predecessor cut":   func(c *Chain) { c.Links[2].Prev = strings.Repeat("d", 64) },
		"link removed":      func(c *Chain) { c.Links = append(c.Links[:2], c.Links[3:]...) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			c := Chain{Root: p.Chain.Root, Links: append([]Link(nil), p.Chain.Links...)}
			mutate(&c)
			if err := VerifyChain(c); err == nil {
				t.Fatalf("%s: chain verified when it should not have", name)
			}
		})
	}
}

// Wrong key and altered pack are different problems with different fixes, and
// a verifier that reports them identically sends someone hunting the wrong one.
func TestWrongKeyIsReportedAsWrongKey(t *testing.T) {
	packBytes, sig, _ := load(t)
	otherPriv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x09}, ed25519.SeedSize))
	otherPub := otherPriv.Public().(ed25519.PublicKey)

	_, err := Verify(packBytes, sig, otherPub)
	if err == nil {
		t.Fatal("a different key verified the pack")
	}
	if !strings.Contains(err.Error(), "not the key named in the pack") {
		t.Fatalf("want a key-mismatch message, got %q", err)
	}
}

func TestMalformedInputsRejected(t *testing.T) {
	packBytes, sig, pub := load(t)

	if err := VerifySeal(nil, sig, pub); err != errEmptyPack {
		t.Fatalf("empty pack: want errEmptyPack, got %v", err)
	}
	if err := VerifySeal(packBytes, sig[:len(sig)-1], pub); err != errBadSignature {
		t.Fatalf("short signature: want errBadSignature, got %v", err)
	}
	if err := VerifySeal(packBytes, sig, pub[:len(pub)-1]); err != errBadPublicKey {
		t.Fatalf("short key: want errBadPublicKey, got %v", err)
	}
	if _, err := Verify([]byte("{not json"), sig, pub); err == nil {
		t.Fatal("invalid JSON verified")
	}
	if _, err := ParsePublicKey([]byte("not a pem file")); err == nil {
		t.Fatal("a non-PEM key parsed")
	}
}

// The fingerprint in the pack must be the SHA-256 of the DER public key, which
// is what `openssl pkey -pubin -outform DER | openssl dgst -sha256` produces.
func TestKeyFingerprintMatchesPack(t *testing.T) {
	packBytes, _, pub := load(t)
	fp, err := KeyFingerprint(pub)
	if err != nil {
		t.Fatalf("fingerprint: %v", err)
	}
	var p Pack
	if err := json.Unmarshal(packBytes, &p); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if fp != p.VerifyKey {
		t.Fatalf("fingerprint mismatch\n computed: %s\n in pack:  %s", fp, p.VerifyKey)
	}
}
