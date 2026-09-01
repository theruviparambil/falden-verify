# A real sealed pack

This is a genuine Falden evidence pack, not a mock-up. It was produced on 1 September 2026 against a real GitHub organisation, sealed with Falden's production signing key, and timestamped by an independent authority. Everything in this directory is what a customer receives.

Check it yourself. That is the entire point of publishing it.

| File | What it is |
|---|---|
| `pack.json` | The pack. 360,503 bytes. |
| `pack.json.sig` | Detached Ed25519 signature over every byte of it. |
| `pack.json.tsr` | RFC 3161 timestamp token from freetsa.org. |
| `falden.pub` | Falden's public verification key. |
| `freetsa-cacert.pem`, `freetsa-tsa.crt` | FreeTSA's certificate chain, so the timestamp is checkable offline. |

## Check the seal

```
go run .. -key falden.pub pack.json
```

Or without running anything of ours:

```sh
digest=$(openssl dgst -sha256 -r pack.json | cut -d' ' -f1)
printf 'falden-pack-ed25519-v1\n%s\n' "$digest" > message.bin
openssl pkeyutl -verify -pubin -inkey falden.pub -rawin -in message.bin -sigfile pack.json.sig
```

Both print success. Now break it:

```sh
sed 's/"pull_requests": 58/"pull_requests": 0/' pack.json > tampered.json
openssl dgst -sha256 -r tampered.json | cut -d' ' -f1
```

Rerun the check against `tampered.json` and it fails. One edited number anywhere in the file breaks the signature, which is the property that makes the document worth anything.

## Check the time

```sh
openssl ts -verify -data pack.json -in pack.json.tsr \
  -CAfile freetsa-cacert.pem -untrusted freetsa-tsa.crt
```

That assertion is not Falden's. It comes from a timestamp authority in Germany that has never heard of us, which is the point: every other guarantee in this pack traces back to one private key held by one person, and a claim about time signed with that same key would be worth exactly that person's word.

```sh
openssl ts -reply -in pack.json.tsr -text | grep "Time stamp"
```

## What is actually in it

```sh
python3 -c "
import json; c = json.load(open('pack.json'))['coverage']
print(c['pull_requests'], 'merged pull requests,', c['commits'], 'commits')
print(c['machine_attributed_pull_requests'], 'carried an AI attribution signal')
print(c['machine_attributed_without_independent_approval'], 'of those had no independent approval')
print(c['attribution_no_signal'], 'carried no signal either way')
"
```

58 merged pull requests over ninety days. 40 carried an AI attribution signal and every one of them was merged without an approving review from any account other than one that authored it. 13 of those changed 500 lines or more. 28 carried no authorship signal at all, which is reported as an evidence gap rather than as human-written, because absence of evidence is not evidence of absence.

Zero had an approver independent of every author. That is not a finding about a bad team. It is one developer's own repository, and it is exactly what the measurement is supposed to show.

## Two things worth looking at

**The egress register.** Every outbound request the collector made, sealed inside the pack.

```sh
python3 -c "
import json
e = json.load(open('pack.json'))['egress']
print(e['total'], 'requests to', e['hosts'])
for s in e['shapes']: print(' ', s['count'], s['template'])
bad = [p for p in e['paths'] if any(k in p for k in ('/contents','/files','tarball','blobs'))]
print('paths that could read source:', len(bad))
"
```

Falden claims not to read customer source code. GitHub cannot enforce that claim, because the Pull requests read permission is on its own sufficient to fetch a diff. So the claim is recorded instead of asserted: here is every request that was made, sealed along with everything else. Grep it.

**The pseudonyms.** People appear as `p_` labels. The salt that resolves them is not here and never leaves the customer's organisation. Machine accounts stay legible, because a bot is not a person and which agent wrote a change is the finding.

## What this does not prove

That the measurements are correct. That collection was complete. That any control is deficient.

Falden supplies a record and issues no opinion. A verified seal means the document in front of you is the document that was sealed. Everything past that is your judgement.
