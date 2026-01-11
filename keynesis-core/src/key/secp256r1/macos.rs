use super::{P256Signature, P256r1PublicKey};
use crate::key::SharedSecret;
use anyhow::{anyhow, ensure, Context as _, Result};
use core_foundation::{base::TCFType as _, data::CFData, dictionary::CFDictionary};
use security_framework::{
    access_control::{ProtectionMode, SecAccessControl},
    item::Location,
    key::{Algorithm, GenerateKeyOptions, KeyType, SecKey, Token},
    passwords_options::AccessControlOptions,
};

const TAG: &str = "uk.co.genuine.key";

#[derive(Clone)]
pub struct P256r1PrivateKey {
    key: SecKey,
    deletable: bool,
}

impl P256r1PublicKey {
    fn to_sec_key(&self, attributes: &CFDictionary) -> Result<SecKey> {
        let key_data = CFData::from_buffer(&self.0);
        unsafe {
            let mut error = std::ptr::null_mut();

            let sec_key = security_framework_sys::key::SecKeyCreateWithData(
                key_data.as_concrete_TypeRef(),
                attributes.as_concrete_TypeRef(),
                &mut error,
            );

            if sec_key.is_null() {
                anyhow::bail!(
                    "{:?}",
                    core_foundation::error::CFError::wrap_under_create_rule(error)
                )
            } else {
                Ok(SecKey::wrap_under_create_rule(sec_key))
            }
        }
    }
}

impl P256r1PrivateKey {
    fn new(key: SecKey, deletable: bool) -> Self {
        Self { key, deletable }
    }

    pub fn generate_ephemeral() -> Result<Self> {
        let mut attributes = GenerateKeyOptions::default();
        attributes
            .set_key_type(KeyType::ec())
            .set_size_in_bits(256)
            .set_token(Token::Software)
            .set_label(format!("{TAG}.ephemeral"));

        let key = SecKey::new(&attributes)
            .map_err(|err| anyhow!("{err:?}"))
            .context("Failed to generate SecKey")?;
        Ok(Self::new(key, false))
    }

    /// generate an ephemeral secure enclave key
    pub fn generate() -> Result<Self> {
        let mut attributes = GenerateKeyOptions::default();
        attributes
            .set_key_type(KeyType::ec())
            .set_size_in_bits(256)
            .set_token(Token::SecureEnclave)
            .set_label(TAG)
            .set_access_control(SecAccessControl::create_with_protection(
                Some(ProtectionMode::AccessibleWhenUnlockedThisDeviceOnly),
                AccessControlOptions::PRIVATE_KEY_USAGE
                    .union(AccessControlOptions::USER_PRESENCE)
                    .bits(),
            )?);

        let key = SecKey::new(&attributes)
            .map_err(|err| anyhow!("{err:?}"))
            .context("Failed to generate SecKey")?;
        Ok(Self::new(key, false))
    }

    /// generate a stored in keychain secure enclave key
    pub fn generate_secure_enclave() -> Result<Self> {
        let mut attributes = GenerateKeyOptions::default();
        attributes
            .set_key_type(KeyType::ec())
            .set_size_in_bits(256)
            .set_label(TAG)
            .set_token(Token::SecureEnclave)
            .set_location(Location::DataProtectionKeychain)
            .set_access_control(SecAccessControl::create_with_protection(
                Some(ProtectionMode::AccessibleWhenUnlockedThisDeviceOnly),
                AccessControlOptions::PRIVATE_KEY_USAGE
                    .union(AccessControlOptions::USER_PRESENCE)
                    .bits(),
            )?);
        let key = SecKey::new(&attributes)
            .map_err(|err| anyhow!("{err:?}"))
            .context("Failed to generate SecKey")?;
        Ok(Self::new(key, true))
    }

    pub fn public(&self) -> Result<P256r1PublicKey> {
        let data = self
            .key
            .public_key()
            .ok_or_else(|| anyhow!("Expecting to extract a public key from the SecKey"))?;
        let data = data.external_representation().ok_or_else(|| {
            anyhow!("Expecting to extract the external representation of the public key")
        })?;
        P256r1PublicKey::from_bytes(data.bytes())
    }

    pub fn dh(&self, public_key: &P256r1PublicKey) -> Result<SharedSecret> {
        let algorithm = Algorithm::ECDHKeyExchangeStandardX963SHA256;

        let supported = unsafe {
            security_framework_sys::key::SecKeyIsAlgorithmSupported(
                self.key.as_concrete_TypeRef(),
                security_framework_sys::key::kSecKeyOperationTypeKeyExchange,
                security_framework_sys::key::kSecKeyAlgorithmECDHKeyExchangeStandardX963SHA256,
            )
        };
        ensure!(supported == 1, "Secret key doesn't support key exchange");

        let public_key: SecKey =
            public_key.to_sec_key(&self.key.public_key().unwrap().attributes())?;

        let shared_secret = self
            .key
            .key_exchange(algorithm, &public_key, 32, None)
            .map_err(|err| anyhow!("{err:?}"))
            .context("Failed to perform key exchange")?;

        let shared_secret: [u8; 32] = shared_secret
            .try_into()
            // techincally this error shouldn't happen and if it does it means
            // our assumptions from the function above are wrong.
            .map_err(|_| anyhow!("Failed to convert shared secret to bytes"))?;

        Ok(SharedSecret::new(shared_secret))
    }

    pub fn sign(&self, message: &[u8]) -> Result<P256Signature> {
        let signature = self
            .key
            .create_signature(Algorithm::ECDSASignatureMessageX962SHA256, message)
            .map_err(|err| anyhow!("{err}"))
            .context("Fail to generate signature")?;
        P256Signature::try_from_asn1(&signature).with_context(|| {
            anyhow!(
                "Failed to convert bytes to signature: {}",
                hex::encode(signature)
            )
        })
    }

    /// delete the key from the keychain
    ///
    pub fn delete(self) -> Result<()> {
        if self.deletable {
            self.key.delete().map_err(|err| anyhow!("{err}"))
        } else {
            Ok(())
        }
    }
}

impl std::fmt::Debug for P256r1PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("P256r1PrivateKey").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quickcheck::{Arbitrary, Gen};

    impl Arbitrary for P256r1PrivateKey {
        fn arbitrary(_g: &mut Gen) -> Self {
            P256r1PrivateKey::generate_ephemeral().unwrap()
        }
    }

    #[test]
    fn generate_signature_ephemeral() {
        let sk1 = P256r1PrivateKey::generate_ephemeral().unwrap();
        let pk1 = sk1.public().unwrap();
        const MSG: &[u8] = b"Hello World";
        let signature = sk1.sign(MSG).unwrap();
        assert!(pk1.verify(signature, MSG));

        let sk2 = P256r1PrivateKey::generate_ephemeral().unwrap();
        let pk2 = sk2.public().unwrap();
        assert!(!pk2.verify(signature, MSG));

        sk1.delete().unwrap();
        sk2.delete().unwrap();
    }

    #[test]
    fn generate_dh_ephemerals() {
        let sk1 = P256r1PrivateKey::generate_ephemeral().unwrap();
        let pk1 = sk1.public().unwrap();

        let sk2 = P256r1PrivateKey::generate_ephemeral().unwrap();
        let pk2 = sk2.public().unwrap();

        let ss1 = sk1.dh(&pk2).unwrap();
        let ss2 = sk2.dh(&pk1).unwrap();

        assert_eq!(ss1, ss2);
    }

    #[test]
    #[ignore = "requires the user to authenticate"]
    fn generate_signature_secure_enclave() {
        let sk1 = P256r1PrivateKey::generate().unwrap();
        let pk1 = sk1.public().unwrap();
        const MSG: &[u8] = b"Hello World";
        let signature = sk1.sign(MSG).unwrap();
        assert!(pk1.verify(signature, MSG));

        let sk2 = P256r1PrivateKey::generate().unwrap();
        let pk2 = sk2.public().unwrap();
        assert!(!pk2.verify(signature, MSG));

        sk1.delete().unwrap();
        sk2.delete().unwrap();
    }
}
