use crate::bead::Bead;
use crate::error::BeadSignError;
use bitcoin::consensus::encode::Encodable;
use bitcoin::hashes::{sha256, Hash, HashEngine};
use bitcoin::secp256k1::{Message, Secp256k1};

pub const UNCOMMITTED_SIGHASH_TAG: &[u8] = b"Braidpool/bead/uncommitted/v1";

/// BIP340 tagged hash: SHA256(SHA256(tag) || SHA256(tag) || msg).
pub fn tagged_hash(tag: &[u8], msg: &[u8]) -> [u8; 32] {
    let tag_hash = sha256::Hash::hash(tag);
    let mut engine = sha256::Hash::engine();
    engine.input(tag_hash.as_byte_array());
    engine.input(tag_hash.as_byte_array());
    engine.input(msg);
    sha256::Hash::from_engine(engine).to_byte_array()
}

/// Every bead field except the signature itself, in a fixed order.
pub fn uncommitted_sighash_payload(bead: &Bead) -> Result<Vec<u8>, BeadSignError> {
    let encode = |e: bitcoin::io::Error| BeadSignError::Encode(e.to_string());
    let mut payload = Vec::new();
    bead.uncommitted_metadata
        .extra_nonce_1
        .consensus_encode(&mut payload)
        .map_err(encode)?;
    bead.uncommitted_metadata
        .extra_nonce_2
        .consensus_encode(&mut payload)
        .map_err(encode)?;
    bead.uncommitted_metadata
        .broadcast_timestamp
        .to_consensus_u32()
        .consensus_encode(&mut payload)
        .map_err(encode)?;
    bead.block_header
        .consensus_encode(&mut payload)
        .map_err(encode)?;
    bead.committed_metadata
        .consensus_encode(&mut payload)
        .map_err(encode)?;
    Ok(payload)
}

pub fn uncommitted_sighash(bead: &Bead) -> Result<[u8; 32], BeadSignError> {
    Ok(tagged_hash(
        UNCOMMITTED_SIGHASH_TAG,
        &uncommitted_sighash_payload(bead)?,
    ))
}

/// Check the bead's signature against its own `comm_pub_key`. Needs no secret.
pub fn verify_bead_signature(bead: &Bead) -> Result<(), BeadSignError> {
    let msg = Message::from_digest(uncommitted_sighash(bead)?);
    Secp256k1::verification_only()
        .verify_schnorr(
            &bead.uncommitted_metadata.signature,
            &msg,
            &bead.committed_metadata.comm_pub_key,
        )
        .map_err(|_| BeadSignError::InvalidSignature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::committed_metadata::placeholder_xonly_pubkey;
    use crate::miner_identity::MinerIdentity;
    use crate::uncommitted_metadata::placeholder_bip340_signature;
    use crate::utils::create_test_bead;
    use bitcoin::absolute::Time;
    use bitcoin::{BlockHash, CompactTarget, TapLeafHash, Txid};

    /// Fully deterministic bead: `create_test_bead` draws random extranonces.
    fn fixed_bead() -> Bead {
        let mut bead = create_test_bead(7, None);
        bead.uncommitted_metadata.extra_nonce_1 = 0x0102_0304_0506_0708;
        bead.uncommitted_metadata.extra_nonce_2 = 0x1112_1314_1516_1718;
        bead
    }

    fn signed_bead() -> Bead {
        let mut bead = fixed_bead();
        MinerIdentity::test_fixture().sign_bead(&mut bead).unwrap();
        bead
    }

    #[test]
    fn sighash_of_fixed_bead_is_pinned() {
        // Changing this value changes what every node signs and verifies.
        assert_eq!(
            hex::encode(uncommitted_sighash(&fixed_bead()).unwrap()),
            "a2d5f8880ea762577c42a53e2b149650849c7984f3a83857c6fac33d665be15d"
        );
    }

    #[test]
    fn payload_starts_with_uncommitted_fields_in_order() {
        let bead = fixed_bead();
        let payload = uncommitted_sighash_payload(&bead).unwrap();
        assert_eq!(&payload[0..8], &0x0102_0304_0506_0708u64.to_le_bytes());
        assert_eq!(&payload[8..16], &0x1112_1314_1516_1718u64.to_le_bytes());
        assert_eq!(
            &payload[16..20],
            &bead
                .uncommitted_metadata
                .broadcast_timestamp
                .to_consensus_u32()
                .to_le_bytes()
        );
        assert_eq!(
            &payload[20..100],
            &bitcoin::consensus::serialize(&bead.block_header)[..]
        );
    }

    #[test]
    fn signed_bead_verifies() {
        assert_eq!(verify_bead_signature(&signed_bead()), Ok(()));
    }

    #[test]
    fn placeholder_signature_does_not_verify() {
        let bead = fixed_bead();
        assert_eq!(
            bead.committed_metadata.comm_pub_key,
            placeholder_xonly_pubkey()
        );
        assert_eq!(
            bead.uncommitted_metadata.signature,
            placeholder_bip340_signature()
        );
        assert_eq!(
            verify_bead_signature(&bead),
            Err(BeadSignError::InvalidSignature)
        );
    }

    #[test]
    fn signature_under_another_key_does_not_verify() {
        let mut bead = signed_bead();
        bead.committed_metadata.comm_pub_key = MinerIdentity::generate().pubkey();
        assert_eq!(
            verify_bead_signature(&bead),
            Err(BeadSignError::InvalidSignature)
        );
    }

    type Tamper = (&'static str, fn(&mut Bead));

    #[test]
    fn changing_any_signed_field_breaks_the_signature() {
        let tampers: Vec<Tamper> = vec![
            ("extra_nonce_1", |b| {
                b.uncommitted_metadata.extra_nonce_1 ^= 1
            }),
            ("extra_nonce_2", |b| {
                b.uncommitted_metadata.extra_nonce_2 ^= 1
            }),
            ("broadcast_timestamp", |b| {
                b.uncommitted_metadata.broadcast_timestamp =
                    Time::from_consensus(1_700_000_000).unwrap()
            }),
            ("header.nonce", |b| b.block_header.nonce ^= 1),
            ("header.time", |b| b.block_header.time ^= 1),
            ("transaction_ids", |b| {
                b.committed_metadata
                    .transaction_ids
                    .0
                    .push(Txid::from_byte_array([3u8; 32]))
            }),
            ("parents", |b| {
                b.committed_metadata
                    .parents
                    .push(BlockHash::from_byte_array([9u8; 32]))
            }),
            ("parent_bead_timestamps", |b| {
                b.committed_metadata
                    .parent_bead_timestamps
                    .0
                    .push(Time::from_consensus(1_700_000_000).unwrap())
            }),
            ("payout_address", |b| {
                b.committed_metadata.payout_address.push('x')
            }),
            ("start_timestamp", |b| {
                b.committed_metadata.start_timestamp = Time::from_consensus(1_700_000_000).unwrap()
            }),
            ("min_target", |b| {
                b.committed_metadata.min_target = CompactTarget::from_consensus(0x1d00_fffe)
            }),
            ("weak_target", |b| {
                b.committed_metadata.weak_target = CompactTarget::from_consensus(0x1d00_fffe)
            }),
            ("miner_ip", |b| b.committed_metadata.miner_ip.push('x')),
        ];
        for (field, tamper) in tampers {
            let mut bead = signed_bead();
            tamper(&mut bead);
            assert_eq!(
                verify_bead_signature(&bead),
                Err(BeadSignError::InvalidSignature),
                "changing {field} must invalidate the signature"
            );
        }
    }
}
