# falden-verify

Offline verification of a Falden evidence pack.

An evidence pack is a record of merged software changes: for each one, what wrote it, who approved it, and whether that approver was independent of anyone who authored it. It is produced by [Falden](https://falden.ai) and consumed by the customer's auditors and second line.

This program checks that a pack is what it claims to be. It is published separately from the collector that produces packs, because a verifier supplied only as part of the thing it verifies is not independent evidence of anything. An auditor using Falden's black box to check Falden's own signature is running in a circle.

## What it checks

**The seal.** That Falden's key vouches for every byte of the pack. Not just the hash chain: the coverage counts, every row, the definitions, the not-visible register, the window. If any byte changed after signing, this fails.

**The chain.** That the commit population inside the pack recomputes from its own object identifiers and arrives at the stated root. This is a separate guarantee and it does not require trusting Falden or this program: the object identifiers are git commit ids, and you can confirm they exist in your own clone.

## What it does not check

Whether the measurements are correct. Whether collection was complete. Whether any control is deficient.

Falden supplies a record and issues no opinion. A verified seal means the document in front of you is the document that was sealed. It is not an assurance conclusion, and nothing here should be read as one.

## A real pack to try it on

[`example/`](example/) holds a genuine sealed pack from a real assessment, with its
signature, its timestamp token, and the public key. Verify it, then edit one number in
it and watch the check fail. That takes about two minutes and is more convincing than
anything written here.

## Install

```
go install github.com/theruviparambil/falden-verify@latest
```

Or build from source. There are no dependencies beyond the Go standard library, so there is nothing to audit but this repository.

```
git clone https://github.com/theruviparambil/falden-verify
cd falden-verify
go build
```

## Use

```
falden-verify -key falden.pub pack.json
```

The signature is expected at `pack.json.sig` unless you pass `-sig`. On success:

```
OK
  pack             pack.json
  digest           725335d11bece060f2a447a650ffe378e73c71b8b800819ce9aacd928f7ac55f
  bytes covered    360503   (the whole file)
  chain root       816c3a4122cef214366550c064dd72dd19be167649a6fbbbc9ddd4d9d9dc2ab2
  commit objects   102, recomputed and matching
  key fingerprint  72e91be823e5e1d669a3510ce1d7cf6648325d3d8cea83f7362d42ead37ff1be
```

Exit status is 0 on success and 1 on any failure. `-quiet` suppresses output for scripting.

## You do not have to run this

Every step is reproducible with stock `openssl`. If you would rather not run a binary supplied by the party being checked, this is the whole procedure:

```sh
digest=$(openssl dgst -sha256 -r pack.json | cut -d' ' -f1)
printf 'falden-pack-ed25519-v1\n%s\n' "$digest" > message.bin
openssl pkeyutl -verify -pubin -inkey falden.pub -rawin -in message.bin -sigfile pack.sig
```

That checks the seal. The chain is a loop over SHA-256, specified below, and reimplementing it in whatever language you prefer is a reasonable afternoon.

**If openssl and this program ever disagree, this program is wrong.**

## The formats, so you can reimplement it

**The signed message.** The signature is Ed25519 over exactly these bytes:

```
falden-pack-ed25519-v1\n<sha256 of pack.json, lowercase hex>\n
```

The domain prefix is not decoration. Without it, a signature made over one kind of value could be presented as a signature over another whenever the hex happened to coincide.

There is no canonicalization step. The signature covers the file as written, byte for byte, so you never have to reproduce Falden's JSON serialisation to check it.

**The chain.** Each link hashes its own object id together with the previous link's hash:

```
link_hash(seq, object_id, prev) = sha256(
    "falden-chain-v1" + "\n" +
    decimal(seq)      + "\n" +
    object_id         + "\n" +
    prev              + "\n"
)
```

Sequence numbers start at 1. The first link's `prev` is 64 zeros. The root is the last link's hash. Because each link includes its predecessor, changing any object id changes every hash after it and therefore changes the root.

**The key fingerprint.** The pack names the key it was signed with, as the SHA-256 of the DER-encoded public key:

```sh
openssl pkey -pubin -in falden.pub -outform DER | openssl dgst -sha256
```

This program checks it, so that "you supplied the wrong key" is reported differently from "this pack was altered". Those two failures look identical otherwise.

## What a failure means

A failed verification does not tell you whether the file was altered deliberately, altered accidentally, or paired with the wrong signature. It tells you the document in front of you is not the document that was sealed.

Do not assume the benign explanation.

## Tests

```
go test ./...
```

The fixture in `testdata/` is a real pack signed by a real key. The private half of that key was destroyed after the fixture was generated, so nothing in this repository can produce a new signature. That is the correct set of capabilities for a verifier to have.

## Licence

MIT. See [LICENSE](LICENSE).
