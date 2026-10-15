//! Per-node secp256k1 miner identity used for BIP340 bead signatures.
//!
//! This one secret is the node's whole identity: the BIP340 x-only key committed in every
//! bead, and the secp256k1 key behind the libp2p `PeerId` (see [`MinerIdentity::libp2p_keypair`]).

use crate::bead::sign::{sign_uncommitted_metadata, BeadSignError};
use crate::bead::Bead;
use crate::secret_file::read_or_create_secret;
use bitcoin::secp256k1::{Secp256k1, SecretKey};
use bitcoin::XOnlyPublicKey;
use rand::rngs::OsRng;
use std::fmt;
use std::io::{self, ErrorKind};
use std::path::{Path, PathBuf};
use tracing::info;

/// File name of the secp256k1 miner secret in the data directory.
pub const MINER_SECP256K1_FILENAME: &str = "miner_secp256k1";

/// secp256k1 key used as `CommittedMetadata.comm_pub_key` and to Schnorr-sign
/// uncommitted metadata.
#[derive(Clone)]
pub struct MinerIdentity {
    secret: SecretKey,
    xonly: XOnlyPublicKey,
}

impl fmt::Debug for MinerIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MinerIdentity")
            .field("xonly", &self.xonly)
            .finish_non_exhaustive()
    }
}

impl MinerIdentity {
    /// Deterministic identity for tests that need a shared `comm_pub_key`.
    pub fn test_fixture() -> Self {
        let mut bytes = [0u8; 32];
        bytes[31] = 1;
        Self::from_secret(
            SecretKey::from_slice(&bytes).expect("integer 1 is a valid secp256k1 secret"),
        )
    }

    /// Generate a fresh miner identity (tests and first run).
    pub fn generate() -> Self {
        let secp = Secp256k1::new();
        let (secret, _) = secp.generate_keypair(&mut OsRng);
        Self::from_secret(secret)
    }

    /// Build identity from an existing secret.
    pub fn from_secret(secret: SecretKey) -> Self {
        let secp = Secp256k1::new();
        let keypair = bitcoin::secp256k1::Keypair::from_secret_key(&secp, &secret);
        let (xonly, _) = keypair.x_only_public_key();
        let xonly = XOnlyPublicKey::from_slice(&xonly.serialize())
            .expect("keypair x-only serialize is valid");
        Self { secret, xonly }
    }

    pub fn load_or_generate(datadir: impl AsRef<Path>) -> io::Result<Self> {
        let path = miner_key_path(datadir.as_ref());
        let (bytes, created) = read_or_create_secret(&path, || {
            Ok(Self::generate().secret.secret_bytes().to_vec())
        })?;
        if bytes.len() != 32 {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                format!(
                    "miner secp256k1 key at {} must be 32 bytes, got {}",
                    path.display(),
                    bytes.len()
                ),
            ));
        }
        let secret = SecretKey::from_slice(&bytes).map_err(|e| {
            io::Error::new(
                ErrorKind::InvalidData,
                format!("invalid miner secp256k1 secret at {}: {e}", path.display()),
            )
        })?;
        if created {
            info!(path = %path.display(), "Generated miner secp256k1 identity");
        } else {
            info!(path = %path.display(), "Loaded miner secp256k1 identity");
        }
        Ok(Self::from_secret(secret))
    }

    pub fn xonly(&self) -> XOnlyPublicKey {
        self.xonly
    }

    #[cfg(test)]
    pub(crate) fn secret_for_tests(&self) -> &SecretKey {
        &self.secret
    }

    /// libp2p's secp256k1 key is an ECDSA key, so the transport stays ECDSA; what is shared is
    /// the secret. The x-coordinate of its public key equals [`MinerIdentity::xonly`], so the
    /// resulting `PeerId` can be linked to beads with [`peer_id_matches_xonly`].
    pub fn libp2p_keypair(
        &self,
    ) -> Result<libp2p::identity::Keypair, libp2p::identity::DecodingError> {
        // `try_from_bytes` zeroizes its input on success; clear our copy on failure too.
        let mut bytes = self.secret.secret_bytes();
        let secret = match libp2p::identity::secp256k1::SecretKey::try_from_bytes(&mut bytes) {
            Ok(secret) => secret,
            Err(e) => {
                bytes.fill(0);
                return Err(e);
            }
        };
        Ok(libp2p::identity::secp256k1::Keypair::from(secret).into())
    }

    pub fn sign_bead(&self, bead: &mut Bead) -> Result<(), BeadSignError> {
        bead.committed_metadata.comm_pub_key = self.xonly;
        sign_uncommitted_metadata(bead, &self.secret)
    }
}

fn miner_key_path(datadir: &Path) -> PathBuf {
    datadir.join(MINER_SECP256K1_FILENAME)
}

/// Multihash code of the identity hash function: the digest is the data itself.
const IDENTITY_MULTIHASH_CODE: u64 = 0x00;

/// The BIP340 x-only key of a libp2p public key, if it is a secp256k1 key.
pub fn xonly_from_public_key(public_key: &libp2p::identity::PublicKey) -> Option<XOnlyPublicKey> {
    let compressed = public_key.clone().try_into_secp256k1().ok()?.to_bytes();
    XOnlyPublicKey::from_slice(&compressed[1..33]).ok()
}

/// The BIP340 x-only key embedded in a secp256k1 `PeerId`.
pub fn xonly_from_peer_id(peer_id: &libp2p::PeerId) -> Option<XOnlyPublicKey> {
    let multihash = peer_id.as_ref();
    if multihash.code() != IDENTITY_MULTIHASH_CODE {
        return None;
    }
    let public_key = libp2p::identity::PublicKey::try_decode_protobuf(multihash.digest()).ok()?;
    xonly_from_public_key(&public_key)
}

/// True if `peer_id` is a secp256k1 identity whose x-coordinate equals `comm_pub_key`.
pub fn peer_id_matches_xonly(peer_id: &libp2p::PeerId, comm_pub_key: &XOnlyPublicKey) -> bool {
    xonly_from_peer_id(peer_id).is_some_and(|x| x == *comm_pub_key)
}

/// Whether a connecting peer is acceptable under the key policy.
pub fn peer_meets_key_policy(peer_id: &libp2p::PeerId, require_secp256k1: bool) -> bool {
    !require_secp256k1 || xonly_from_peer_id(peer_id).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::identity::Keypair;
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_dir() -> PathBuf {
        // The counter keeps parallel tests apart even where the clock resolution is coarse.
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "braidpool-miner-id-{}-{nanos}-{n}",
            std::process::id()
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn two_generated_identities_differ() {
        let a = MinerIdentity::generate();
        let b = MinerIdentity::generate();
        assert_ne!(a.xonly(), b.xonly());
    }

    #[test]
    fn test_fixture_is_stable() {
        assert_eq!(
            MinerIdentity::test_fixture().xonly(),
            MinerIdentity::test_fixture().xonly()
        );
    }

    #[test]
    fn debug_omits_secret() {
        let identity = MinerIdentity::test_fixture();
        let debug = format!("{:?}", identity);
        assert!(debug.contains("xonly"));
        assert!(!debug.contains("secret"));
        assert!(!debug.contains(&hex::encode(identity.secret_for_tests().secret_bytes())));
    }

    #[test]
    fn load_or_generate_is_stable() {
        let dir = unique_dir();
        let first = MinerIdentity::load_or_generate(&dir).unwrap();
        let second = MinerIdentity::load_or_generate(&dir).unwrap();
        assert_eq!(first.xonly(), second.xonly());
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn generated_key_file_is_owner_read_only_and_32_bytes() {
        use std::os::unix::fs::PermissionsExt;
        let dir = unique_dir();
        MinerIdentity::load_or_generate(&dir).unwrap();
        let path = dir.join(MINER_SECP256K1_FILENAME);
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o400
        );
        assert_eq!(fs::read(&path).unwrap().len(), 32);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn wrong_length_file_is_an_error_and_is_not_replaced() {
        let dir = unique_dir();
        let path = dir.join(MINER_SECP256K1_FILENAME);
        fs::write(&path, [1u8; 31]).unwrap();
        let err = MinerIdentity::load_or_generate(&dir).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidData);
        assert_eq!(fs::read(&path).unwrap(), vec![1u8; 31]);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn zero_scalar_is_an_error_and_is_not_replaced() {
        let dir = unique_dir();
        let path = dir.join(MINER_SECP256K1_FILENAME);
        fs::write(&path, [0u8; 32]).unwrap();
        let err = MinerIdentity::load_or_generate(&dir).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidData);
        assert_eq!(fs::read(&path).unwrap(), vec![0u8; 32]);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn unreadable_key_path_is_an_error_not_a_new_identity() {
        // A directory at the key path gives a non-NotFound error, which must not regenerate.
        let dir = unique_dir();
        let path = dir.join(MINER_SECP256K1_FILENAME);
        fs::create_dir(&path).unwrap();
        assert!(MinerIdentity::load_or_generate(&dir).is_err());
        assert!(path.is_dir());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn concurrent_first_start_yields_one_identity() {
        use std::sync::{Arc, Barrier};
        let dir = Arc::new(unique_dir());
        let barrier = Arc::new(Barrier::new(8));
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let (dir, barrier) = (Arc::clone(&dir), Arc::clone(&barrier));
                std::thread::spawn(move || {
                    barrier.wait();
                    MinerIdentity::load_or_generate(&*dir).unwrap().xonly()
                })
            })
            .collect();
        let keys: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        assert!(keys.iter().all(|k| *k == keys[0]));
        let again = MinerIdentity::load_or_generate(&*dir).unwrap().xonly();
        assert_eq!(again, keys[0]);
        let _ = fs::remove_dir_all(&*dir);
    }

    #[test]
    fn peer_id_of_derived_key_carries_the_bead_key() {
        let identity = MinerIdentity::generate();
        let peer_id = identity.libp2p_keypair().unwrap().public().to_peer_id();
        assert_eq!(xonly_from_peer_id(&peer_id), Some(identity.xonly()));
        assert!(peer_id_matches_xonly(&peer_id, &identity.xonly()));
    }

    #[test]
    fn matches_for_both_parities_of_the_public_point() {
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

    #[test]
    fn key_policy_matrix() {
        let secp = MinerIdentity::generate()
            .libp2p_keypair()
            .unwrap()
            .public()
            .to_peer_id();
        let ed = Keypair::generate_ed25519().public().to_peer_id();
        // Off: everyone is acceptable.
        assert!(peer_meets_key_policy(&secp, false));
        assert!(peer_meets_key_policy(&ed, false));
        // On: only secp256k1 identities are.
        assert!(peer_meets_key_policy(&secp, true));
        assert!(!peer_meets_key_policy(&ed, true));
    }
}
