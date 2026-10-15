//! Linking a libp2p identity to a bead's `comm_pub_key`.
//!
//! A node's libp2p key is derived from the same 32-byte secret as its BIP340 miner key (see
//! [`crate::miner_identity::MinerIdentity::libp2p_keypair`]). libp2p's secp256k1 public key is
//! the 33-byte compressed point (`02`/`03` followed by x). The bead key is that point's
//! x-coordinate, so the two are linked by comparing x and ignoring the parity byte.
//!
//! A secp256k1 `PeerId` is an identity multihash that contains the encoded public key, so a
//! peer's miner key can be read straight from its `PeerId`.

use bitcoin::XOnlyPublicKey;
use libp2p::identity::PublicKey;
use libp2p::PeerId;

/// Multihash code of the identity hash function: the digest is the data itself.
const IDENTITY_MULTIHASH_CODE: u64 = 0x00;

/// The BIP340 x-only key of a libp2p public key, if it is a secp256k1 key.
///
/// Returns `None` for any other key type (for example ed25519).
pub fn xonly_from_public_key(public_key: &PublicKey) -> Option<XOnlyPublicKey> {
    let compressed = public_key.clone().try_into_secp256k1().ok()?.to_bytes();
    XOnlyPublicKey::from_slice(&compressed[1..33]).ok()
}

/// The BIP340 x-only key embedded in a secp256k1 `PeerId`.
///
/// Returns `None` if the `PeerId` is not an identity multihash of a secp256k1 key
/// (for example an ed25519 PeerId, or a hashed PeerId of a large RSA key).
pub fn xonly_from_peer_id(peer_id: &PeerId) -> Option<XOnlyPublicKey> {
    let multihash = peer_id.as_ref();
    if multihash.code() != IDENTITY_MULTIHASH_CODE {
        return None;
    }
    let public_key = PublicKey::try_decode_protobuf(multihash.digest()).ok()?;
    xonly_from_public_key(&public_key)
}

/// True if `peer_id` is a secp256k1 identity whose x-coordinate equals `comm_pub_key`.
pub fn peer_id_matches_xonly(peer_id: &PeerId, comm_pub_key: &XOnlyPublicKey) -> bool {
    xonly_from_peer_id(peer_id).is_some_and(|x| x == *comm_pub_key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::miner_identity::MinerIdentity;
    use libp2p::identity::Keypair;

    #[test]
    fn peer_id_of_derived_key_carries_the_bead_key() {
        let identity = MinerIdentity::generate();
        let peer_id = identity.libp2p_keypair().unwrap().public().to_peer_id();
        assert_eq!(xonly_from_peer_id(&peer_id), Some(identity.xonly()));
        assert!(peer_id_matches_xonly(&peer_id, &identity.xonly()));
    }

    #[test]
    fn matches_for_both_parities_of_the_public_point() {
        // The compressed libp2p key has an 02 or 03 prefix depending on the parity of y,
        // while the bead key drops it. Both parities must link.
        let (mut even, mut odd) = (0, 0);
        for _ in 0..64 {
            let identity = MinerIdentity::generate();
            let public = identity.libp2p_keypair().unwrap().public();
            let compressed = public.clone().try_into_secp256k1().unwrap().to_bytes();
            match compressed[0] {
                0x02 => even += 1,
                0x03 => odd += 1,
                other => panic!("unexpected prefix {other:#x}"),
            }
            assert_eq!(xonly_from_public_key(&public), Some(identity.xonly()));
            assert!(peer_id_matches_xonly(
                &public.to_peer_id(),
                &identity.xonly()
            ));
        }
        assert!(even > 0 && odd > 0, "64 keys should cover both parities");
    }

    #[test]
    fn different_miner_does_not_match() {
        let a = MinerIdentity::generate();
        let b = MinerIdentity::generate();
        let peer_a = a.libp2p_keypair().unwrap().public().to_peer_id();
        assert!(!peer_id_matches_xonly(&peer_a, &b.xonly()));
    }

    #[test]
    fn ed25519_peer_id_has_no_miner_key() {
        let ed = Keypair::generate_ed25519();
        assert!(xonly_from_public_key(&ed.public()).is_none());
        assert!(xonly_from_peer_id(&ed.public().to_peer_id()).is_none());
    }

    #[test]
    fn same_secret_gives_the_same_peer_id() {
        let secret = bitcoin::secp256k1::SecretKey::from_slice(&[0x11u8; 32]).unwrap();
        let a = MinerIdentity::from_secret(secret).libp2p_keypair().unwrap();
        let b = MinerIdentity::from_secret(secret).libp2p_keypair().unwrap();
        assert_eq!(a.public().to_peer_id(), b.public().to_peer_id());
    }

    #[test]
    fn bead_verifies_under_the_key_read_from_the_signers_peer_id() {
        use crate::bead::sign::verify_uncommitted_signature;
        use crate::utils::create_test_bead;
        let identity = MinerIdentity::generate();
        let peer_id = identity.libp2p_keypair().unwrap().public().to_peer_id();

        let mut bead = create_test_bead(1, None);
        identity.sign_bead(&mut bead).unwrap();
        verify_uncommitted_signature(&bead).unwrap();

        // The key a peer reads out of the PeerId is the key the bead is signed under.
        let from_peer = xonly_from_peer_id(&peer_id).unwrap();
        assert_eq!(from_peer, bead.committed_metadata.comm_pub_key);
        assert!(peer_id_matches_xonly(
            &peer_id,
            &bead.committed_metadata.comm_pub_key
        ));
    }
}
