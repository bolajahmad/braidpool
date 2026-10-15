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
use std::collections::HashSet;
use std::fmt;
use std::io::{self, ErrorKind};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
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

    /// The libp2p keypair for this node, derived from the miner secret.
    ///
    /// libp2p's secp256k1 key is an ECDSA key, so the transport stays ECDSA; what is shared is
    /// the secret. The secret is normalised to the even-y form first: a secret `d` and its
    /// negation `n - d` have the same x-only key but opposite parity, so without this one bead
    /// key could be run as two different `PeerId`s. After normalising, the public key always
    /// starts with `02` and a bead key corresponds to exactly one `PeerId`. BIP340 signing is
    /// unaffected (it normalises internally), and `xonly_from_public_key` rejects the `03` form.
    pub fn libp2p_keypair(
        &self,
    ) -> Result<libp2p::identity::Keypair, libp2p::identity::DecodingError> {
        let canonical = canonical_secret(&self.secret);
        // `try_from_bytes` zeroizes its input on success; clear our copy on failure too.
        let mut bytes = canonical.secret_bytes();
        let secret = match libp2p::identity::secp256k1::SecretKey::try_from_bytes(&mut bytes) {
            Ok(secret) => secret,
            Err(e) => {
                bytes.fill(0);
                return Err(e);
            }
        };
        Ok(libp2p::identity::secp256k1::Keypair::from(secret).into())
    }

    /// Refuse to run with a denied key. For the built-in list its secret is publicly known, so
    /// anyone could sign as this node.
    ///
    /// # Errors
    /// `InvalidData` naming the key if it is on `denylist`.
    pub fn ensure_allowed(&self, denylist: &KeyDenylist) -> io::Result<()> {
        if denylist.contains(&self.xonly) {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                format!(
                    "miner key {} is on the key denylist; delete the miner_secp256k1 file \
                     to generate a new one",
                    self.xonly
                ),
            ));
        }
        Ok(())
    }

    /// ECDH shared point with the holder of the x-only key `peer`; see [`ecdh_shared_point`].
    pub fn ecdh_shared_point(&self, peer: &XOnlyPublicKey) -> [u8; 64] {
        ecdh_shared_point(&self.secret, peer)
    }

    pub fn sign_bead(&self, bead: &mut Bead) -> Result<(), BeadSignError> {
        bead.committed_metadata.comm_pub_key = self.xonly;
        sign_uncommitted_metadata(bead, &self.secret)
    }
}

/// The even-y form of `secret`: `secret` itself if its public point has an even y, else its
/// negation `n - secret`.
///
/// An x-only key stands for two points, P and -P, and a secret `d` and its negation have the
/// same x-only key. Anything that must agree on one point (the libp2p key, ECDH) therefore
/// always uses this form, for ephemeral keys as well as the miner key, so no code ever has to
/// guess a parity.
pub fn canonical_secret(secret: &SecretKey) -> SecretKey {
    let secp = Secp256k1::new();
    let (_, parity) =
        bitcoin::secp256k1::Keypair::from_secret_key(&secp, secret).x_only_public_key();
    match parity {
        bitcoin::secp256k1::Parity::Even => *secret,
        bitcoin::secp256k1::Parity::Odd => secret.negate(),
    }
}

/// ECDH shared point between `secret` and the holder of the x-only key `peer`.
///
/// Returns the 64 bytes `x || y` of `canonical_secret(secret) * lift_x(peer)`. The peer's key is
/// lifted to its even-y point, and the secret is first reduced to its even-y form, so both sides
/// compute the identical point, y included. With a raw secret, about half of all pairs would
/// disagree on y, and any KDF that hashes the compressed point (parity byte) would give two
/// different keys. The caller derives its key from this point with its own domain-separated
/// hash; this is a primitive, not a finished ECIES.
pub fn ecdh_shared_point(secret: &SecretKey, peer: &XOnlyPublicKey) -> [u8; 64] {
    let peer_point = bitcoin::secp256k1::PublicKey::from_x_only_public_key(
        *peer,
        bitcoin::secp256k1::Parity::Even,
    );
    bitcoin::secp256k1::ecdh::shared_secret_point(&peer_point, &canonical_secret(secret))
}

/// Secrets `1..=KNOWN_SMALL_SECRETS` are public by construction: anyone can compute `k * G`.
pub const KNOWN_SMALL_SECRETS: u32 = 1024;

/// Secret keys published with the BIP340 test vectors. Vector 0 (secret 3) is already covered by
/// the small secrets, so it is not repeated here.
const BIP340_TEST_VECTOR_SECRETS: [&str; 3] = [
    "B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF",
    "C90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B14E5C9",
    "0B432B2677937381AEF05BB02A66ECD012773062CF3FA2549E44F58ED2401710",
];

/// Miner keys that must never be accepted because their secrets are publicly known, so anyone
/// could sign as them.
///
/// This is a validation policy, not part of the encoding: changing the list never changes the
/// wire format. The default list ([`KeyDenylist::known_secrets`]) is built from secrets, not
/// from hard-coded public keys; see `docs/identity_specifications.md` for the groups.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct KeyDenylist {
    keys: HashSet<XOnlyPublicKey>,
}

impl KeyDenylist {
    /// A list that denies nothing (the default, and what tests use).
    pub fn empty() -> Self {
        Self::default()
    }

    /// The production default: the keys of the secrets `1..=KNOWN_SMALL_SECRETS` (this includes
    /// the generator point, secret 1) and of the BIP340 test-vector secrets.
    pub fn known_secrets() -> Self {
        let mut list = Self::empty();
        for k in 1..=KNOWN_SMALL_SECRETS {
            let mut bytes = [0u8; 32];
            bytes[28..].copy_from_slice(&k.to_be_bytes());
            if let Ok(secret) = SecretKey::from_slice(&bytes) {
                list.keys.insert(MinerIdentity::from_secret(secret).xonly());
            }
        }
        for hex in BIP340_TEST_VECTOR_SECRETS {
            if let Some(secret) = hex::decode(hex)
                .ok()
                .and_then(|bytes| SecretKey::from_slice(&bytes).ok())
            {
                list.keys.insert(MinerIdentity::from_secret(secret).xonly());
            }
        }
        list
    }

    /// This list plus one more denied key.
    pub fn with_key(mut self, key: XOnlyPublicKey) -> Self {
        self.keys.insert(key);
        self
    }

    /// True if `key` is denied.
    pub fn contains(&self, key: &XOnlyPublicKey) -> bool {
        self.keys.contains(key)
    }

    /// Number of denied keys.
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// True if the list denies nothing.
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

static ACTIVE_KEY_DENYLIST: OnceLock<KeyDenylist> = OnceLock::new();

/// Install the denylist this process enforces. Call once, at startup, before any bead is
/// verified. Returns the list back if one is already installed (or was already read).
pub fn set_active_key_denylist(list: KeyDenylist) -> Result<(), KeyDenylist> {
    ACTIVE_KEY_DENYLIST.set(list)
}

/// The denylist this process enforces; empty unless [`set_active_key_denylist`] installed one.
pub fn active_key_denylist() -> &'static KeyDenylist {
    ACTIVE_KEY_DENYLIST.get_or_init(KeyDenylist::default)
}

fn miner_key_path(datadir: &Path) -> PathBuf {
    datadir.join(MINER_SECP256K1_FILENAME)
}

/// Multihash code of the identity hash function: the digest is the data itself.
const IDENTITY_MULTIHASH_CODE: u64 = 0x00;

/// The BIP340 x-only key of a libp2p public key, if it is a canonical secp256k1 key.
///
/// Only the even-y form (`02` prefix) counts: that is what [`MinerIdentity::libp2p_keypair`]
/// produces, so each bead key has exactly one `PeerId`. The odd-y form of the same x-only key
/// (`03` prefix) and every other key type give `None`.
pub fn xonly_from_public_key(public_key: &libp2p::identity::PublicKey) -> Option<XOnlyPublicKey> {
    let compressed = public_key.clone().try_into_secp256k1().ok()?.to_bytes();
    if compressed[0] != 0x02 {
        return None;
    }
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
    fn derived_libp2p_key_is_always_the_even_y_form() {
        // A bead key must map to one PeerId: whatever the parity of the secret's public point,
        // the derived libp2p key is the 02 form, and its x is the bead key.
        let (mut even_secrets, mut odd_secrets) = (0, 0);
        for _ in 0..64 {
            let identity = MinerIdentity::generate();
            let secp = bitcoin::secp256k1::Secp256k1::new();
            let (_, parity) =
                bitcoin::secp256k1::Keypair::from_secret_key(&secp, identity.secret_for_tests())
                    .x_only_public_key();
            match parity {
                bitcoin::secp256k1::Parity::Even => even_secrets += 1,
                bitcoin::secp256k1::Parity::Odd => odd_secrets += 1,
            }
            let public = identity.libp2p_keypair().unwrap().public();
            let compressed = public.clone().try_into_secp256k1().unwrap().to_bytes();
            assert_eq!(compressed[0], 0x02);
            assert_eq!(xonly_from_public_key(&public), Some(identity.xonly()));
            assert!(peer_id_matches_xonly(
                &public.to_peer_id(),
                &identity.xonly()
            ));
        }
        assert!(
            even_secrets > 0 && odd_secrets > 0,
            "64 secrets should include both parities"
        );
    }

    #[test]
    fn a_secret_and_its_negation_are_one_peer() {
        let identity = MinerIdentity::generate();
        let negated = MinerIdentity::from_secret(identity.secret_for_tests().negate());
        assert_eq!(identity.xonly(), negated.xonly());
        assert_eq!(
            identity.libp2p_keypair().unwrap().public().to_peer_id(),
            negated.libp2p_keypair().unwrap().public().to_peer_id()
        );
    }

    #[test]
    fn odd_y_libp2p_key_is_not_a_miner_identity() {
        // Someone who builds the 03 form by hand (the un-normalised secret) gets a PeerId whose
        // x equals a bead key, but it is not the canonical one and carries no miner key.
        let identity = MinerIdentity::generate();
        let canonical_keypair = identity.libp2p_keypair().unwrap();
        let canonical = canonical_keypair.public();
        // The canonical secret has an even-y public point; its negation has the odd-y one.
        let canonical_secret = canonical_keypair
            .try_into_secp256k1()
            .unwrap()
            .secret()
            .to_bytes();
        let mut odd_bytes = bitcoin::secp256k1::SecretKey::from_slice(&canonical_secret)
            .unwrap()
            .negate()
            .secret_bytes();
        let odd_secret =
            libp2p::identity::secp256k1::SecretKey::try_from_bytes(&mut odd_bytes).unwrap();
        let odd =
            libp2p::identity::Keypair::from(libp2p::identity::secp256k1::Keypair::from(odd_secret))
                .public();
        let odd_compressed = odd.clone().try_into_secp256k1().unwrap().to_bytes();
        assert_eq!(odd_compressed[0], 0x03);
        assert_eq!(
            odd.clone().try_into_secp256k1().unwrap().to_bytes()[1..],
            canonical.clone().try_into_secp256k1().unwrap().to_bytes()[1..]
        );
        assert_ne!(odd.to_peer_id(), canonical.to_peer_id());
        assert_eq!(xonly_from_public_key(&odd), None);
        assert!(!peer_meets_key_policy(&odd.to_peer_id(), true));
        assert!(peer_meets_key_policy(&odd.to_peer_id(), false));
        assert!(peer_meets_key_policy(&canonical.to_peer_id(), true));
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

    #[test]
    fn ecdh_with_canonical_keys_always_agrees() {
        // Both sides only know the other's x-only key. With canonical secrets they compute the
        // same point, y included, for every pair (both parities occur among 500 pairs).
        let mut odd_secret_seen = false;
        for _ in 0..500 {
            let a = MinerIdentity::generate();
            let b = MinerIdentity::generate();
            let secp = bitcoin::secp256k1::Secp256k1::new();
            let (_, parity) =
                bitcoin::secp256k1::Keypair::from_secret_key(&secp, a.secret_for_tests())
                    .x_only_public_key();
            odd_secret_seen |= parity == bitcoin::secp256k1::Parity::Odd;
            assert_eq!(
                a.ecdh_shared_point(&b.xonly()),
                b.ecdh_shared_point(&a.xonly())
            );
        }
        assert!(odd_secret_seen);
    }

    #[test]
    fn ecdh_with_raw_secrets_would_disagree_about_half_the_time() {
        // Documents why canonical secrets are used: lifting the peer's x-only key to even y and
        // multiplying by a raw secret gives a point whose y depends on the secret's parity.
        let mut disagreements = 0;
        for _ in 0..200 {
            let a = MinerIdentity::generate();
            let b = MinerIdentity::generate();
            let raw = |sk: &SecretKey, peer: &XOnlyPublicKey| {
                let point = bitcoin::secp256k1::PublicKey::from_x_only_public_key(
                    *peer,
                    bitcoin::secp256k1::Parity::Even,
                );
                bitcoin::secp256k1::ecdh::shared_secret_point(&point, sk)
            };
            if raw(a.secret_for_tests(), &b.xonly()) != raw(b.secret_for_tests(), &a.xonly()) {
                disagreements += 1;
            }
        }
        assert!(
            disagreements > 40,
            "expected roughly half of 200 pairs to disagree, got {disagreements}"
        );
    }

    #[test]
    fn ecdh_is_the_same_for_a_secret_and_its_negation() {
        let a = MinerIdentity::generate();
        let a_negated = MinerIdentity::from_secret(a.secret_for_tests().negate());
        let b = MinerIdentity::generate();
        assert_eq!(
            a.ecdh_shared_point(&b.xonly()),
            a_negated.ecdh_shared_point(&b.xonly())
        );
    }

    #[test]
    fn canonical_secret_is_idempotent_and_even_y() {
        let secp = bitcoin::secp256k1::Secp256k1::new();
        for _ in 0..64 {
            let sk = *MinerIdentity::generate().secret_for_tests();
            let canonical = canonical_secret(&sk);
            assert_eq!(canonical_secret(&canonical), canonical);
            let (_, parity) =
                bitcoin::secp256k1::Keypair::from_secret_key(&secp, &canonical).x_only_public_key();
            assert_eq!(parity, bitcoin::secp256k1::Parity::Even);
        }
    }

    #[test]
    fn default_denylist_covers_the_known_secret_groups() {
        let list = KeyDenylist::known_secrets();
        // Small secrets: the generator point (secret 1), 2G and 3G, up to the last one.
        for hex in [
            "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
            "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
            "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
        ] {
            assert!(list.contains(&hex.parse().unwrap()), "{hex}");
        }
        let mut last = [0u8; 32];
        last[28..].copy_from_slice(&KNOWN_SMALL_SECRETS.to_be_bytes());
        let last_key = MinerIdentity::from_secret(SecretKey::from_slice(&last).unwrap()).xonly();
        assert!(list.contains(&last_key));
        let mut beyond = [0u8; 32];
        beyond[28..].copy_from_slice(&(KNOWN_SMALL_SECRETS + 1).to_be_bytes());
        let beyond_key =
            MinerIdentity::from_secret(SecretKey::from_slice(&beyond).unwrap()).xonly();
        assert!(!list.contains(&beyond_key));
        // BIP340 test vectors (public keys as published with the vectors).
        for hex in [
            "dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659",
            "dd308afec5777e13121fa72b9cc1b7cc0139715309b086c960e18fd969774eb8",
            "25d1dff95105f5253c4022f628a996ad3a0d95fbf21d468a1b33f8c160d8f517",
        ] {
            assert!(list.contains(&hex.parse().unwrap()), "{hex}");
        }
        assert_eq!(list.len(), KNOWN_SMALL_SECRETS as usize + 3);
    }

    #[test]
    fn denylist_does_not_touch_ordinary_keys() {
        let list = KeyDenylist::known_secrets();
        for _ in 0..64 {
            assert!(!list.contains(&MinerIdentity::generate().xonly()));
        }
        assert!(KeyDenylist::empty().is_empty());
    }

    #[test]
    fn extra_denied_key_is_honoured() {
        let key = MinerIdentity::generate().xonly();
        let list = KeyDenylist::empty().with_key(key);
        assert!(list.contains(&key));
        assert_eq!(list.len(), 1);
    }

    #[test]
    fn negated_secret_of_a_denied_key_is_denied_too() {
        // k and n-k have the same x-only key, so negating a known secret does not escape the list.
        let list = KeyDenylist::known_secrets();
        let mut one = [0u8; 32];
        one[31] = 1;
        let negated = SecretKey::from_slice(&one).unwrap().negate();
        assert!(list.contains(&MinerIdentity::from_secret(negated).xonly()));
    }

    #[test]
    fn ensure_allowed_refuses_the_test_fixture_and_accepts_a_random_key() {
        let list = KeyDenylist::known_secrets();
        let err = MinerIdentity::test_fixture()
            .ensure_allowed(&list)
            .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidData);
        assert!(err.to_string().contains("denylist"));
        MinerIdentity::generate().ensure_allowed(&list).unwrap();
        // An empty list never refuses.
        MinerIdentity::test_fixture()
            .ensure_allowed(&KeyDenylist::empty())
            .unwrap();
    }
}
