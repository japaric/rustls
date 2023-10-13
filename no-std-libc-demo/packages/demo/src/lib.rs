#![no_std]

extern crate alloc;

use alloc::sync::Arc;

use ministd::time::{SystemTime, UNIX_EPOCH};
use pki_types::UnixTime;
use rustls::cipher_suite::CipherSuiteCommon;
use rustls::client::danger::ServerCertVerifier;
use rustls::client::WebPkiServerVerifier;
use rustls::crypto::CryptoProvider;
use rustls::time_provider::{GetCurrentTime, TimeProvider};
use rustls::{CipherSuite, SupportedCipherSuite, Tls13CipherSuite};

mod aead;
mod hash;
mod hmac;
mod kx;
mod verify;

pub static CRYPTO_PROVIDER: &'static dyn CryptoProvider = &DemoCryptoProvider;

#[derive(Debug)]
struct DemoCryptoProvider;

impl CryptoProvider for DemoCryptoProvider {
    fn fill_random(&self, bytes: &mut [u8]) -> Result<(), rustls::crypto::GetRandomFailed> {
        use rand_core::RngCore;
        rand_core::OsRng
            .try_fill_bytes(bytes)
            .map_err(|_| rustls::crypto::GetRandomFailed)
    }

    fn default_cipher_suites(&self) -> &'static [rustls::SupportedCipherSuite] {
        ALL_CIPHER_SUITES
    }

    fn default_kx_groups(&self) -> &'static [&'static dyn rustls::crypto::SupportedKxGroup] {
        kx::ALL_KX_GROUPS
    }
}

static ALL_CIPHER_SUITES: &[rustls::SupportedCipherSuite] = &[TLS13_CHACHA20_POLY1305_SHA256];

pub fn time_provider() -> TimeProvider {
    TimeProvider::new(DemoTimeProvider)
}

struct DemoTimeProvider;

impl GetCurrentTime for DemoTimeProvider {
    fn get_current_time(&self) -> Result<UnixTime, ()> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(drop)
            .map(UnixTime::since_unix_epoch)
    }
}

static TLS13_CHACHA20_POLY1305_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls13(&Tls13CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
            hash_provider: &hash::Sha256,
        },
        hmac_provider: &hmac::Sha256Hmac,
        aead_alg: &aead::Chacha20Poly1305,
    });

pub fn certificate_verifier(roots: rustls::RootCertStore) -> Arc<dyn ServerCertVerifier> {
    Arc::new(WebPkiServerVerifier::new_with_algorithms(
        roots,
        verify::ALGORITHMS,
    ))
}
