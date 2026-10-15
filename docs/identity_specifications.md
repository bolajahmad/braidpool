# Miner Identity & Signatures

Beads replace blocks, and every bead must be attributable to the node that produced it.
That attribution is `CommittedMetadata::comm_pub_key`, and the bead is authenticated by
`UnCommittedMetadata::signature`. The party that is paid is identified separately, by
`payout_address` (see [Open decisions](#open-decisions)).

**Rule.** Braidpool supports exactly one public-key format and exactly one signature
scheme for anything it defines itself:

* public keys are **BIP340 x-only secp256k1 keys**, 32 bytes;
* signatures are **BIP340 Schnorr signatures**, 64 bytes.

No other encoding, curve, hash-type byte or signature scheme is accepted, even for
compatibility. This avoids the variation Bitcoin tolerates (compressed, uncompressed,
DER, ECDSA, sighash suffixes).

Status labels used below: **Implemented** (in this repository now) and **Planned**
(specified here, not yet implemented).

## Bead public key (Implemented)

| | |
| --- | --- |
| Rust type | `bitcoin::XOnlyPublicKey` |
| Wire | exactly 32 raw bytes, no length prefix and no parity byte |
| JSON / database | lowercase hex of `XOnlyPublicKey::serialize()` (64 hex chars) |
| Curve point | the x-coordinate only. The y-coordinate is the **even-y** lift defined by BIP340 `lift_x` |

A note on terminology: early BIP340 drafts chose y by a quadratic-residue test. The final
BIP340, and the libraries Braidpool uses, choose the **even** y. This document and the
code use even-y.

Rejected, and the bead is invalid: a 33-byte compressed key (`02`/`03` + x), a 65-byte
uncompressed key (`04` + x + y), any DER-encoded key, any 32 bytes that are not a valid
x-coordinate on the curve. `parse_xonly_pubkey` enforces this for the database and RPC
paths, and `CommittedMetadata` decoding enforces it on the wire.

## Bead signature (Implemented)

| | |
| --- | --- |
| Rust type | `bitcoin::secp256k1::schnorr::Signature` |
| Wire | exactly 64 raw bytes, `R.x (32) \|\| s (32)` |
| JSON / database | lowercase hex of those 64 bytes |
| Scheme | BIP340, deterministic (`sign_schnorr_no_aux_rand`): no auxiliary randomness, the nonce is derived from the secret, the public key and the message, so the same bead signed twice gives the same signature |

### Message

```
digest  = tagged_hash("Braidpool/bead/uncommitted/v1", payload)
tagged_hash(tag, m) = SHA256( SHA256(tag) || SHA256(tag) || m )      (BIP340)
payload = extra_nonce_1                  u64, little-endian, 8 bytes
       || extra_nonce_2                  u64, little-endian, 8 bytes
       || broadcast_timestamp            u32, little-endian, 4 bytes (consensus value)
       || block_header                   80 bytes, Bitcoin consensus encoding
       || committed_metadata             Braidpool consensus encoding (includes comm_pub_key)
```

The signature itself and nothing else of the uncommitted metadata is excluded. Because
the header and the committed metadata, including `comm_pub_key`, are inside the signed
bytes, a valid signature cannot be moved onto a different bead, and cannot be checked
against a different key.

### Signing

`MinerIdentity::sign_bead` first sets `comm_pub_key` to the node's x-only key, then
signs the digest. Implementations must not hand-adjust the secret for odd-y public
keys: the BIP340 signing routine already negates the secret internally when the public
point has odd y.

### Verification

`verify_uncommitted_signature` recomputes the digest and verifies the 64-byte signature
against the `comm_pub_key` carried in the same bead. No other key is consulted.
`extend_verified` rejects a bead with an invalid signature before `Braid::extend` on
every ingestion path (gossip, initial sync, RPC `addbead`, database reload, audit DAG).
Locally formed beads are signed by the node itself immediately before insertion.

Rejected, and the bead is invalid: a signature that is not exactly 64 bytes, an ECDSA
DER signature, a trailing sighash-type byte, and any signature that does not verify.

### Signature tags (Proposed registry)

Every signed object type has its own tag so that a signature made for one can never be
valid for another. Convention: `Braidpool/<object>/<purpose>/v<N>`. The tag names below
are proposals for maintainers to review; the rule that matters is that no two object
types share a tag.

| Tag | Signed object | Status |
| --- | --- | --- |
| `Braidpool/bead/uncommitted/v1` | bead authentication (above) | Implemented |
| `Braidpool/peer-binding/v1` | statement binding a PeerId to `comm_pub_key` | Reserved; unused if the libp2p key is derived from the miner secret (see below) |
| `Braidpool/ecies/...` | any future signed ECIES handshake data | Reserved |

## Miner key file (Implemented)

The secret behind `comm_pub_key` is stored at `datadir/miner_secp256k1`.

| | |
| --- | --- |
| Content | exactly 32 raw bytes: the secret scalar, big-endian |
| Mode | `0o400` (owner read-only), on Unix |
| Created by | `MinerIdentity::load_or_generate`, via `secret_file::read_or_create_secret` |

**Why `0o400`.** Anyone who can read this file can forge beads as this miner. The file
is owner-read-only so no other local user can read it, and no process (including this
one) can modify it by accident.

**Creation is atomic.** A new key is written to a temporary sibling that is created with
mode `0o400` from the first instant, flushed to disk, and then published under its final
name with a hard link, which fails if the name already exists. Consequences:

* the secret never exists on disk with wider permissions (the previous code wrote the
  file first and restricted it afterwards, leaving a short window);
* the final name never holds a partial file;
* two processes starting at once on the same datadir end up with the same key: one
  creates it, the other reads it. No process can overwrite another's key.

If the filesystem does not support hard links, the file is written directly with
`create_new` and the same mode, which still never overwrites.

**Loading rules.**

* Only a missing file (`NotFound`) causes a key to be generated.
* Any other read error aborts startup. An identity is never regenerated over a path
  that could not be read.
* The path must be a regular file. A directory or other object there is an error.
* The content must be exactly 32 bytes and a valid, non-zero scalar below the curve
  order. Anything else is an error and the file is left untouched.
* A file whose mode is not `0o400` is tightened to `0o400` and a warning is logged.

**Operator-visible changes.** A node with an existing `miner_secp256k1` keeps it. What can
differ: a key file with group/other permission bits is tightened at startup; an unreadable
or malformed key file stops the node with an error instead of being replaced;
`MinerConfig.miner_pubkey` in the TOML configuration is unused.

## libp2p peer key (Implemented)

There is one secret per node, `datadir/miner_secp256k1`. The libp2p key is derived from it
by `MinerIdentity::libp2p_keypair`, so the node's `PeerId` and the `comm_pub_key` in every
bead it forms come from the same key.

| | |
| --- | --- |
| Derivation | the 32-byte miner secret loaded as a libp2p `secp256k1::SecretKey` |
| Public key | 33-byte compressed secp256k1 point (`02`/`03` followed by x) |
| `PeerId` | identity multihash of the encoded public key (`16Uiu2HA…`); it contains the key |
| Transport signatures | **ECDSA** (SHA-256, DER). This is libp2p's secp256k1 scheme; it is not BIP340 |
| Used by | Kademlia, floodsub, identify (`/braidpool/identify/1.0.0`) and the QUIC/TLS handshake |
| Retired | `datadir/keystore` (random ed25519). It is no longer read or written. If present, the node logs a warning and ignores it; it is not deleted |

What is shared is the key, not the signature scheme.

* The x-coordinate of the libp2p public key (`bytes[1..33]` of the 33-byte form) **is**
  the bead `comm_pub_key`. The parity byte is discarded and does not affect the
  comparison; keys of both parities link.
* Any peer can read the miner key out of a secp256k1 `PeerId` and compare it with a
  bead's `comm_pub_key`. No additional signature is needed. The helpers are
  `miner_identity::xonly_from_public_key`, `xonly_from_peer_id` and `peer_id_matches_xonly`.
* Braidpool-defined signatures (beads and anything added later) are always BIP340
  Schnorr. "Schnorr only" applies to what Braidpool defines, not to libp2p's handshake.
* One secret per machine. Running the same secret on two machines yields the same
  `PeerId`, which the network treats as one node. Two nodes on one machine need separate
  data directories.

Evidence:

* A standalone experiment on the local branch `spike/libp2p-secp256k1` (15 checks) showed
  that libp2p 0.55 with QUIC, identify, ping and floodsub works with a secret-derived
  secp256k1 identity, and that libp2p does not keep ed25519 peers out by itself.
* The unit tests in `miner_identity` cover both parities of the public point, the
  stability of the `PeerId` for a given secret, and a bead that verifies under the key
  read from its signer's `PeerId`. The `behaviour` swarm tests run the real
  `BraidPoolBehaviour` on derived secp256k1 identities.

Peer policy (Implemented):

* libp2p accepts an ed25519 peer on a secp256k1 node, so the restriction to secp256k1
  identities is enforced by Braidpool. With `--require-secp256k1-peers`, a node
  disconnects any peer whose `PeerId` does not carry a miner key, as soon as the
  connection is established (`peer_meets_key_policy`).
* The `PeerId` is enough. The transport handshake proves the remote controls the key
  behind its `PeerId`, and a secp256k1 `PeerId` contains that key, so no identify
  payload is trusted and there is nothing for a peer to forge.
* The flag is **off by default** for now, because the bootnode still uses an ed25519
  key and a node that enforced the policy would disconnect from it and have no network.
  With the flag off, such peers are allowed and logged. The default is to be switched on
  when the bootnode key is rotated.
* `getpeerinfo` reports each peer's `bead_key` (hex x-only key), or `null` for a peer
  without a miner key. This is the key to compare with a bead's `comm_pub_key`.
* Beads are **not** rejected based on the peer that delivered them: floodsub relays
  beads, so the sender is often not the author. A bead is valid or not by its own
  signature.

Not done yet (later phases):

* **Protocol strings.** They are unchanged (`/braidpool/identify/1.0.0` and the others).
  They must be bumped together with the bead encoding change, so that old and new nodes
  do not connect and then fail to decode.
* **Bootnode.** `BOOTNODES` and the seed addresses in `main.rs` still name the old
  ed25519 bootnode PeerId. A secp256k1 node can dial it, since libp2p accepts both key
  types, but the constants must be replaced once the bootnode operator rotates its key.

**Operator-visible changes.** Every node's `PeerId` changes when it first starts on this
version, because it now comes from the miner key. Bootstrap addresses that include a
`/p2p/<PeerId>` of one of your own nodes must be updated. Addresses without a PeerId
(`--addnode=/ip4/…/udp/…/quic-v1`) are unaffected.

### Key reuse across schemes

One secret is used under ECDSA (libp2p) and BIP340 Schnorr (beads). The position taken
here:

* The security proofs of ECDSA and of BIP340 each assume the key is used only for that
  scheme; a joint proof is not part of either standard. No practical attack on the
  combination is known. This is an accepted, documented risk, pending the
  Cryptographer review.
* A signature of one scheme is not valid in the other (different verification
  equations), and the messages are domain-separated: libp2p signs SHA-256 of its own
  prefixed handshake data; beads sign a BIP340 tagged hash under a `Braidpool/…` tag.
* The exposure that matters is an attacker steering what the key signs. Therefore,
  **the identity key must never sign attacker-supplied data under either scheme**.
  In libp2p's handshake the signed content is built by the node (its own ephemeral
  certificate key); bead payloads are built by the node.
* Any new signed object needs its own tag and must be built by the node.
* Costs: two implementations (`k256` and `libsecp256k1`) handle the same secret, and a
  compromise exposes transport and bead identity together.

## ECIES between mining nodes (Planned, non-normative, proof of concept)

The intended use is private messaging between miners (for example coordination for
payout signing). No implementation is required yet. The requirement for when it is
written:

An x-only key stands for two points, P and -P. ECDH on them gives shared points with the
same x and different y. The default secp256k1 ECDH hashes the compressed point, which
includes the parity byte, so the two parties can derive different secrets. In a test of
2000 random keys, a sender that lifts the recipient's x-only key to even y and a
recipient using its raw secret disagreed 1005 times. Either of these fixes it (0
disagreements in the same test):

1. derive the key from the **x-coordinate only** of the shared point; or
2. use the **BIP340-normalised secret** (negated if its public point has odd y) on the
   side that holds the secret.

Further requirements: the sender uses a fresh ephemeral key per message (forward
secrecy); whether signing and decryption use the same key or separate keys is open; do
not use a BIP341-tweaked output key for ECIES with the untweaked identity secret.

## Open decisions

* **Whom EDCA credits, and the payout field.** `payout_address` is currently a free
  string validated only at the Stratum edge. Options: credit the payout script; one
  address per key; or a separate x-only payout key. Undecided.
* **Binding the key to the proof of work.** The signature authenticates the signer; the
  coinbase commitment must also bind the committed metadata, including `comm_pub_key`,
  to the work. This needs confirming outside audit mode.
* **Known-key denylist.** A configurable list of keys that must never be accepted (for
  example the secp256k1 generator point, whose secret is 1).
* **Network of payout addresses.** Stratum currently accepts mainnet addresses only.
