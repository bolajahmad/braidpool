use super::*;
use crate::bead::sign::verify_bead_signature;
use crate::utils::create_test_bead;
use std::fs;
use std::io::ErrorKind;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

fn unique_dir() -> PathBuf {
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
    assert_ne!(a.pubkey(), b.pubkey());
}

#[test]
fn test_fixture_is_stable() {
    assert_eq!(
        MinerIdentity::test_fixture().pubkey(),
        MinerIdentity::test_fixture().pubkey()
    );
}

#[test]
fn debug_omits_secret() {
    let identity = MinerIdentity::test_fixture();
    let debug = format!("{:?}", identity);
    assert!(debug.contains("pubkey"));
    assert!(!debug.contains("secret"));
    assert!(!debug.contains(&hex::encode(identity.keypair.secret_bytes())));
}

#[test]
fn load_or_generate_is_stable() {
    let dir = unique_dir();
    let first = MinerIdentity::load_or_generate(&dir).unwrap();
    let second = MinerIdentity::load_or_generate(&dir).unwrap();
    assert_eq!(first.pubkey(), second.pubkey());
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
                MinerIdentity::load_or_generate(&*dir).unwrap().pubkey()
            })
        })
        .collect();
    let keys: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    assert!(keys.iter().all(|k| *k == keys[0]));
    assert_eq!(
        MinerIdentity::load_or_generate(&*dir).unwrap().pubkey(),
        keys[0]
    );
    let _ = fs::remove_dir_all(&*dir);
}

#[test]
fn sign_bead_sets_comm_pub_key_and_verifies() {
    let identity = MinerIdentity::generate();
    let mut bead = create_test_bead(1, None);
    identity.sign_bead(&mut bead).unwrap();
    assert_eq!(bead.committed_metadata.comm_pub_key, identity.pubkey());
    assert_eq!(verify_bead_signature(&bead), Ok(()));
}

#[test]
fn signing_is_deterministic_for_fixed_aux_randomness() {
    let identity = MinerIdentity::test_fixture();
    let bead = create_test_bead(1, None);
    let sign = |aux: [u8; 32]| {
        let mut b = bead.clone();
        identity.sign_bead_with_aux_rand(&mut b, &aux).unwrap();
        b.uncommitted_metadata.signature
    };
    assert_eq!(sign([7u8; 32]), sign([7u8; 32]));
    assert_ne!(sign([7u8; 32]), sign([8u8; 32]));
}

#[test]
fn sign_bead_uses_fresh_aux_randomness() {
    let identity = MinerIdentity::test_fixture();
    let (mut a, mut b) = (create_test_bead(1, None), create_test_bead(1, None));
    b.uncommitted_metadata = a.uncommitted_metadata.clone();
    identity.sign_bead(&mut a).unwrap();
    identity.sign_bead(&mut b).unwrap();
    assert_ne!(
        a.uncommitted_metadata.signature,
        b.uncommitted_metadata.signature
    );
}

#[cfg(unix)]
#[test]
fn loose_key_file_permissions_are_tightened() {
    use std::os::unix::fs::PermissionsExt;
    let dir = unique_dir();
    let path = dir.join(MINER_SECP256K1_FILENAME);
    let original = MinerIdentity::generate();
    fs::write(&path, original.keypair.secret_bytes()).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    let loaded = MinerIdentity::load_or_generate(&dir).unwrap();
    assert_eq!(loaded.pubkey(), original.pubkey());
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o400
    );
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn creating_the_key_leaves_no_temporary_files() {
    let dir = unique_dir();
    MinerIdentity::load_or_generate(&dir).unwrap();
    let names: Vec<_> = fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(
        names,
        vec![std::ffi::OsString::from(MINER_SECP256K1_FILENAME)]
    );
    let _ = fs::remove_dir_all(&dir);
}
