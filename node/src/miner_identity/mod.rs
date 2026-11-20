use bitcoin::{
    secp256k1::{Keypair, Message, Secp256k1, SecretKey},
    XOnlyPublicKey,
};
use rand::{rngs::OsRng, RngCore};
use std::{
    fmt,
    io::{self, ErrorKind},
    path::{Path, PathBuf},
};
use tracing::info;

use crate::{
    bead::{sign::uncommitted_sighash, Bead},
    error::BeadSignError,
    miner_identity::key_file::read_or_create_secret,
};

mod key_file;

pub const MINER_SECP256K1_FILENAME: &str = "miner_secp256k1.key";
fn miner_key_path(datadir: &Path) -> PathBuf {
    datadir.join(MINER_SECP256K1_FILENAME)
}

#[derive(Clone)]
pub struct MinerIdentity {
    keypair: Keypair,
    pubkey: XOnlyPublicKey,
}

impl fmt::Debug for MinerIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MinerIdentity")
            .field("pubkey", &self.pubkey)
            .finish_non_exhaustive()
    }
}

impl MinerIdentity {
    pub fn from_secret(secret: SecretKey) -> Self {
        let keypair = Keypair::from_secret_key(&Secp256k1::signing_only(), &secret);
        let (pubkey, _) = keypair.x_only_public_key();
        Self { keypair, pubkey }
    }

    pub fn generate() -> Self {
        Self::from_secret(SecretKey::new(&mut OsRng))
    }

    pub fn load_or_generate(datadir: impl AsRef<Path>) -> io::Result<Self> {
        let path = miner_key_path(datadir.as_ref());
        let (bytes, created) = read_or_create_secret(&path, || {
            Ok(Self::generate().keypair.secret_bytes().to_vec())
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

    pub fn pubkey(&self) -> XOnlyPublicKey {
        self.pubkey
    }

    /// Set `comm_pub_key` to this identity, then sign. Call after every other field is final.
    pub fn sign_bead(&self, bead: &mut Bead) -> Result<(), BeadSignError> {
        let mut aux_rand = [0u8; 32];
        OsRng
            .try_fill_bytes(&mut aux_rand)
            .map_err(|e| BeadSignError::Randomness(e.to_string()))?;
        self.sign_bead_with_aux_rand(bead, &aux_rand)
    }

    fn sign_bead_with_aux_rand(
        &self,
        bead: &mut Bead,
        aux_rand: &[u8; 32],
    ) -> Result<(), BeadSignError> {
        bead.committed_metadata.comm_pub_key = self.pubkey;
        let msg = Message::from_digest(uncommitted_sighash(bead)?);
        bead.uncommitted_metadata.signature =
            Secp256k1::signing_only().sign_schnorr_with_aux_rand(&msg, &self.keypair, aux_rand);
        Ok(())
    }

    /// Deterministic identity for tests that need a shared `comm_pub_key`.
    #[cfg(test)]
    pub fn test_fixture() -> Self {
        let mut bytes = [0u8; 32];
        bytes[31] = 1;
        Self::from_secret(
            SecretKey::from_slice(&bytes).expect("integer 1 is a valid secp256k1 secret"),
        )
    }
}

#[cfg(test)]
mod tests;
