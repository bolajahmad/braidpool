# Miner Identity & Signatures

Beads replace blocks, and every bead must be attributable to the node that produced it.
That attribution is `CommittedMetadata::comm_pub_key`, and the bead is authenticated by
`UnCommittedMetadata::signature`. The party that is paid is identified separately, by
`payout_address` (see [Proposals](#proposals-non-normative)).

**Rule.** Braidpool supports exactly one public-key format and exactly one signature
scheme for anything it defines itself:

* public keys are **BIP340 x-only secp256k1 keys**, 32 bytes;
* signatures are **BIP340 Schnorr signatures**, 64 bytes.

No other encoding, curve, hash-type byte or signature scheme is accepted, even for
compatibility. This avoids the variation Bitcoin tolerates (compressed, uncompressed,
DER, ECDSA, sighash suffixes).

**How this document is organised.**

| Part | Status | Contents |
| --- | --- | --- |
| [Specification](#specification) | Normative, implemented | key format, signature, key file, libp2p identity, protocol 2.0.0 |
| [Migration notes](#migration-notes-for-operators) | Operational | what changes for a node operator, step by step |
| [Questions for the Cryptographer review](#questions-for-the-cryptographer-review) | Open | precise questions, with the context needed to answer them |
| [Proposals](#proposals-non-normative) | Non-normative | payout field, ECIES, hardening and follow-ups |
| [Status](#status) | Summary | implemented, partly done, not done |

---

# Specification

## Bead public key

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

## Bead signature

| | |
| --- | --- |
| Rust type | `bitcoin::secp256k1::schnorr::Signature` |
| Wire | exactly 64 raw bytes, `R.x (32) \|\| s (32)`; `UnCommittedMetadata` is exactly 84 bytes |
| JSON / database | lowercase hex of those 64 bytes (128 hex chars) |
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

Only the signature field is excluded from what is signed. Because the header and the
committed metadata, including `comm_pub_key`, are inside the signed bytes, a valid
signature cannot be moved onto a different bead, and cannot be checked against a
different key.

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

### Signature tags

Every signed object type has its own tag so that a signature made for one can never be
valid for another. Convention: `Braidpool/<object>/<purpose>/v<N>`. The tag names are
proposals for maintainers to review; the rule that matters is that no two object types
share a tag.

| Tag | Signed object | Status |
| --- | --- | --- |
| `Braidpool/bead/uncommitted/v1` | bead authentication (above) | Implemented |
| `Braidpool/ecies/...` | any future signed ECIES handshake data | Reserved |

A tag for binding a PeerId to the miner key was considered and is **not needed**: the
libp2p key is derived from the miner secret, so the link is structural (see below).

## Miner key file

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

## libp2p peer key

There is one secret per node, `datadir/miner_secp256k1`. The libp2p key is derived from it
by `MinerIdentity::libp2p_keypair`, so the node's `PeerId` and the `comm_pub_key` in every
bead it forms come from the same key.

| | |
| --- | --- |
| Derivation | the 32-byte miner secret loaded as a libp2p `secp256k1::SecretKey` |
| Public key | 33-byte compressed secp256k1 point (`02`/`03` followed by x) |
| `PeerId` | identity multihash of the encoded public key (`16Uiu2HA…`); it contains the key |
| Transport signatures | **ECDSA** (SHA-256, DER). This is libp2p's secp256k1 scheme; it is not BIP340 |
| Used by | Kademlia, floodsub, identify and the QUIC/TLS handshake |
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

* A standalone experiment (branch `spike/libp2p-secp256k1`, 15 checks) showed that
  libp2p 0.55 with QUIC, identify, ping and floodsub works with a secret-derived
  secp256k1 identity, and that libp2p does not keep ed25519 peers out by itself.
* The unit tests in `miner_identity` cover both parities of the public point, the
  stability of the `PeerId` for a given secret, and a bead that verifies under the key
  read from its signer's `PeerId`. The `behaviour` swarm tests run the real
  `BraidPoolBehaviour` on derived secp256k1 identities.

### Peer policy

libp2p accepts an ed25519 peer on a secp256k1 node, so the restriction to secp256k1
identities is enforced by Braidpool.

* **Key policy** (`--require-secp256k1-peers`, **on by default**; `=false` turns it
  off). A peer whose `PeerId` does not carry a miner key is ignored (see quarantine
  below) from the moment the connection is established (`peer_meets_key_policy`).
* The `PeerId` is enough. The transport handshake proves the remote controls the key
  behind its `PeerId`, and a secp256k1 `PeerId` contains that key, so no identify
  payload is trusted and there is nothing for a peer to forge.
* **Version policy.** A peer whose identify `protocol_version` is not ours is ignored as
  soon as it identifies itself (`is_current_protocol_version`). This policy has no
  switch: such a peer cannot decode our beads.
* `getpeerinfo` reports each peer's `bead_key` (hex x-only key), or `null` for a peer
  without a miner key.
* Beads are **not** rejected based on the peer that delivered them: floodsub relays
  beads, so the sender is often not the author. A bead is valid or not by its own
  signature.

**Quarantine, not disconnect.** An ignored peer is left connected but unused: it is not
added to the peer manager, to floodsub's partial view or to the DHT, and it is logged
once. Disconnecting is worse. A disconnected floodsub peer redials immediately, and in a
test with a peer on another protocol version that was **2,252 reconnects in 6 seconds and
about 220% CPU on the rejecting node** (debug build, same machine); quarantining the same
peer used about **0.1% CPU**. The protocols themselves do not negotiate with an
incompatible peer, so an idle connection cannot exchange beads.

## Protocol 2.0.0

The `Bead` wire encoding changed in this release: 32-byte x-only keys and 64-byte
Schnorr signatures replace 33-byte compressed keys and DER signatures. Nodes on
different versions cannot exchange beads, so the network is cut over as a whole.

| Name | Value | How it separates old from new |
| --- | --- | --- |
| Kademlia | `/braidpool/kad/2.0.0` | a real stream protocol: peers on another version fail to negotiate, so the DHTs stay apart |
| Bead sync | `/braidpool/bead-sync/2.0.0` | a real stream protocol: requests to an old peer fail as unsupported |
| Gossip topic | `braidpool_channel/2.0.0` | floodsub's own name (`/floodsub/1.0.0`) is fixed by libp2p and cannot carry a version, so the topic carries it; old and new peers share no topic |
| Identify | `/braidpool/identify/2.0.0` | only the `protocol_version` string inside identify messages. Nothing checks it by itself; the version policy above does |

A test pins every name to `PROTOCOL_VERSION`, and another that a peer identifying with
the old string fails the check.

**Database format version.** The SQLite databases carry `PRAGMA user_version = 2`.

* A new database is stamped with 2.
* A database with version 0 (created before versioning) that holds beads cannot be
  read: its rows have 33-byte keys and DER signatures. The node stops at startup with an
  error that says what to delete, instead of failing later with a decode error on the
  first row.
* A version-0 database with no beads is stamped in place.
* A database with a higher version than the node knows is refused.

---

# Migration notes for operators

These apply when upgrading a node from before protocol 2.0.0.

1. **Your miner key is kept.** If `datadir/miner_secp256k1` exists it is reused, and
   becomes the node's `comm_pub_key` and the source of its `PeerId`. If you never ran a
   build that created it, one is generated on first start.
2. **Your `PeerId` changes.** It now comes from the miner key instead of the old random
   ed25519 key. Anything that names the old `PeerId` (a `/p2p/<PeerId>` in someone's
   `--addnode`, a monitoring script) must be updated. Addresses without a PeerId
   (`--addnode=/ip4/…/udp/…/quic-v1`) are unaffected. `getpeerinfo` shows the PeerId and
   the `bead_key` of each peer.
3. **`datadir/keystore` is ignored.** The node logs a warning and does not delete it.
   You can delete it once you are on 2.0.0.
4. **Old databases must be removed.** If `braidpool.db` holds beads from before 2.0.0,
   startup stops with a message naming the file. Stop the node and delete
   `braidpool.db`, `braidpool.db-wal` and `braidpool.db-shm` (and `audit.db*` if you run
   audit mode and it is reported). The braid is rebuilt from the network. The miner key
   is not affected.
5. **No rolling upgrade.** Old and new nodes cannot exchange beads, and a 2.0.0 node
   ignores old peers (and the reverse). Upgrade a whole set of nodes together. There is
   no downgrade path for a database that has been stamped with version 2.
6. **Bootstrap.** The hard-coded bootnode still runs the old protocol with an ed25519
   `PeerId`; a 2.0.0 node dials it, finds that it speaks 1.0.0, and ignores it. Until
   the bootnode operator upgrades it and `BOOTNODES`, `SEED_DNS` and `ADDR_REFRENCE`
   in `node/src/main.rs` carry its new `PeerId`, a fresh node has no bootstrap peer.
   Use `--addnode` to connect nodes explicitly in the meantime.
7. **Flags.**
   * `--require-secp256k1-peers` is on by default; `--require-secp256k1-peers=false`
     allows peers without a miner key. Such peers are still ignored if they speak
     another protocol version, which any pre-2.0.0 node does.
8. **Two nodes on one machine** need separate data directories, because the `PeerId`
   comes from the key in the data directory.
9. **File permissions.** A key file that is not `0o400` is tightened at startup with a
   warning. If a key file is unreadable or malformed the node stops rather than create a
   new identity.
10. **Operational note.** A peer on another protocol version is logged once and then
    left idle. It still holds a connection until it closes.

---

# Questions for the Cryptographer review

The design choices below have been made and are implemented; each question says what the
reviewer is asked to confirm or reject, and what the fallback is.

**Q1. One secret under ECDSA (libp2p) and BIP340 Schnorr (beads).**
The libp2p secp256k1 key is the miner secret; libp2p signs with ECDSA (RFC 6979
deterministic nonce, SHA-256, DER) via `k256`, beads sign with BIP340 via
`libsecp256k1`. The position taken: the proofs for each scheme assume the key is used
only for that scheme, no practical attack on the combination is known, messages are
domain-separated (libp2p hashes its own prefixed handshake data; beads use a tagged hash),
and the key never signs attacker-supplied data under either scheme.
*Is this acceptable? If not, the fallback is a separate transport key plus a signed
binding (`Braidpool/peer-binding/v1`), at the cost of a second secret and a PeerId that no
longer proves the miner key by itself.*

**Q2. What does the libp2p handshake sign, and can an outsider influence it?**
Q1 relies on the claim that, in the QUIC/TLS handshake, the signed content is built by
the node (its ephemeral certificate key) and not chosen by the peer. This was reasoned
from the `libp2p-tls` source, not tested adversarially.
*Please confirm for `libp2p-tls` 0.6.x, and for identify (which does not sign).*

**Q3. Deterministic BIP340 signing.**
Beads are signed with `sign_schnorr_no_aux_rand`, so a signature is a pure function of
the key and the bead. That helps reproducibility and testing. BIP340 recommends fresh
auxiliary randomness as hardening against fault and side-channel attacks.
*Is deterministic signing acceptable for a node that signs automatically and
continuously, or should auxiliary randomness be added?*

**Q4. Is the signed payload unambiguous?**
The payload concatenates fixed-width fields with `committed_metadata`, whose
`TxIdVec`, parents, timestamps and strings are length-prefixed by consensus encoding.
*Please confirm there are no two distinct beads with the same payload bytes, and that
the 80-byte header plus metadata cannot be re-split differently.*

**Q5. Is the key bound to the proof of work?**
The signature authenticates the signer, but it does not by itself bind the signer to the
work. In audit mode `compute_audit_bead_hash` covers the header and the committed
metadata (and so the key). In normal mode the coinbase OP_RETURN carries only a short
commitment, and no check ties the full committed metadata, including `comm_pub_key`
and `payout_address`, to the header. If nothing does, someone who sees a valid header could
re-sign it under their own key and address and claim its weight.
*Is that attack real in normal mode, and what is the smallest commitment that closes it
(for example a hash of the committed metadata in the OP_RETURN)?*

**Q6. Two PeerIds for one bead key.**
The link between a `PeerId` and `comm_pub_key` drops the parity byte. The secret `d` and
its negation `n - d` have the same x-only key but different compressed keys (`02` vs `03`),
hence two different `PeerId`s that both match one `comm_pub_key`. Their owner can run both.
*Is it acceptable that one bead key can appear as two peers? If not, the rule could be
to require the even-y form (normalise the secret before deriving the libp2p key).*

**Q7. ECIES between mining nodes.** (Not implemented; this is to settle the design.)
An x-only key stands for two points. ECDH over them yields the same x and different y,
and the default secp256k1 ECDH hashes the compressed point including parity. In a test
of 2,000 random keys a sender using the even-y lift of the recipient's key and a recipient
using its raw secret disagreed 1,005 times; hashing only the x-coordinate, or using the
BIP340-normalised secret, gave 0.
*Which of the two should be specified? Should signing and decryption use the same key,
or separate keys? Is ephemeral-static ECDH with a fresh ephemeral key per message enough,
or is sender authentication needed?*

**Q8. Known-secret keys.**
The generator point G (secret 1) and similar keys have publicly known secrets, so
anyone can sign as them. A configurable denylist is proposed (see below).
*Is a denylist enough, or should the protocol forbid a fixed set of keys?*

---

# Proposals (non-normative)

## Payout field

`payout_address` is currently a free string, validated only at the Stratum edge, and
there only as a mainnet address (`require_network(Bitcoin)`; the check came with the audit
mode in #509, which itself requires mainnet). Under EDCA each miner puts its payout outputs in the coinbase of the
beads it mines, so the payout scripts are covered by the header's merkle root, but which
miner a bead's weight belongs to still needs an explicit field.

| Option | What it means | Trade-off |
| --- | --- | --- |
| A. Credit the payout script | EDCA keys everything on the recipient; `comm_pub_key` only identifies the node that vouched for the bead | Matches what is paid; keeps multi-tenant nodes. No stable node identity for penalties |
| B. One address per key | The address is derived from, or registered once for, `comm_pub_key` | Clean aggregation. Breaks nodes serving many workers unless each has its own key; puts payout control on a hot key |
| C. Separate x-only payout key | Replace the string with a 32-byte x-only payout key (P2TR output key) in the committed metadata; the node key still signs | Both fields on x-only, fewer bytes, no string parsing; the payout key can be cold |

Recommendation: C, once the team decides whom EDCA credits. Notes:

* The same miner using several payout keys cannot be detected (keys are free), and does
  not need to be: weight is per bead and outputs are per script. The cost is more
  coinbase outputs, bounded by EDCA's dust rule.
* P2TR outputs are 43 bytes against 31 for P2WPKH, about 39% more per output, which
  matters for the already large coinbase. Wallet and exchange support for P2TR is not
  universal. Raw x-only keys differ from BIP86-tweaked wallet addresses.
* The Stratum address check should follow the configured network (as
  `template_creator.rs` already does for cpunet) and report the expected network.
* The payout script must be validated on every ingestion path, not only at Stratum.

## ECIES between mining nodes

Purpose (from `general_considerations.md`): keys "necessary for encrypted communication
with this miner" and out-of-band contact information, for example coordination of payout
signing. The specification says encrypted miner communication builds on StratumV2, which
may already cover part of it. This stays a proof of concept; settle Q7 first.

## Hardening and follow-ups

* **Typed beads.** Parse into an `UnverifiedBead` that can only become a `SignedBead`
  through verification, and make `Braid::extend` accept only `SignedBead`, so an unsigned
  bead cannot reach the DAG. Today this is enforced by calling `extend_verified`.
* **Known-key denylist.** A configurable list (default: G and test keys) checked in
  `extend_verified`. It is a validation policy, not part of the encoding.
* **Block list behaviour.** Quarantine avoids the redial loop. libp2p's allow/block-list
  behaviour would deny known-bad `PeerId`s cheaply at connection time; it changes
  `BraidPoolBehaviour`, so it is left as a decision.
* **One name for the RPC field.** The bead key appears as `comm_pub_key` (code),
  `comm_pubkey` (spec) and `common_pubkey` (RPC and CLI help). Pick one for the RPC.
* **Dead configuration.** `MinerConfig.miner_pubkey` is unused and can be removed.
* **Database constraints.** `CHECK(length(comm_pub_key) = 32)` and
  `CHECK(length(signature) = 64)` would catch bad writes at the database.
* **Functional test.** A test with two nodes that checks `getpeerinfo` reports the peer
  and its `bead_key`, and that an incompatible peer is ignored. Needs `bitcoin-node`.
* **Per-worker keys.** Nodes serving many workers sign every worker's beads with one key.
  Per-worker keys give finer attribution at the price of more hot keys.

---

# Status

| Item | State |
| --- | --- |
| BIP340 x-only key and Schnorr signature on beads | Implemented |
| Signature verified on every ingestion path | Implemented |
| Atomic `0o400` key file | Implemented |
| libp2p identity derived from the miner key | Implemented |
| `getpeerinfo` reports each peer's miner key | Implemented |
| Key policy and version policy, quarantine | Implemented |
| Protocol 2.0.0 names, topic, DB format version | Implemented |
| Bootnode on 2.0.0 and its `PeerId` in `main.rs` | **Not done** (operator action) |
| Binding the key to the proof of work (Q5) | **Open** |
| Cryptographer review (Q1 to Q8) | **Open** |
| Payout field (A, B or C) | **Open** |
| ECIES | Proof of concept only |
| Typed `SignedBead`, denylist, block list | Proposed |
