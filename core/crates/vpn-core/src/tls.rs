use std::path::Path;
use std::sync::{Arc, OnceLock};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{ring, CryptoProvider};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};

use crate::error::{Error, Result};

fn provider() -> Arc<CryptoProvider> {
    static P: OnceLock<Arc<CryptoProvider>> = OnceLock::new();
    Arc::clone(P.get_or_init(|| Arc::new(ring::default_provider())))
}

fn build(roots: RootCertStore) -> Result<Arc<ClientConfig>> {
    let mut cfg = ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .map_err(|e| Error::internal(format!("TLS setup failed: {e}")))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(cfg))
}

/// Client configuration for one request: bundled Mozilla roots by default,
/// only the certificates in `ca_file` when given, or no verification at all
/// when `verify` is false.
pub fn client_config(verify: bool, ca_file: Option<&Path>) -> Result<Arc<ClientConfig>> {
    if !verify {
        let mut cfg = ClientConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .map_err(|e| Error::internal(format!("TLS setup failed: {e}")))?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerification(provider())))
            .with_no_client_auth();
        cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        return Ok(Arc::new(cfg));
    }
    match ca_file {
        None => {
            static DEFAULT: OnceLock<Arc<ClientConfig>> = OnceLock::new();
            if let Some(c) = DEFAULT.get() {
                return Ok(Arc::clone(c));
            }
            let roots = RootCertStore {
                roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
            };
            let cfg = build(roots)?;
            Ok(Arc::clone(DEFAULT.get_or_init(|| cfg)))
        }
        Some(path) => {
            let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(path)
                .map_err(|e| {
                    Error::config(format!("cannot read ca_file `{}`: {e}", path.display()))
                })?
                .collect::<std::result::Result<_, _>>()
                .map_err(|e| {
                    Error::config(format!("invalid certificate in `{}`: {e}", path.display()))
                })?;
            let mut roots = RootCertStore::empty();
            let (added, _) = roots.add_parsable_certificates(certs);
            if added == 0 {
                return Err(Error::config(format!(
                    "ca_file `{}` contains no usable certificates",
                    path.display()
                )));
            }
            build(roots)
        }
    }
}

pub fn server_name(host: &str) -> Result<ServerName<'static>> {
    ServerName::try_from(host.to_string())
        .map_err(|_| Error::config(format!("`{host}` is not a valid TLS server name")))
}

/// Accepts any certificate (verify_tls = false) but still checks handshake
/// signatures so the connection is at least internally consistent.
#[derive(Debug)]
struct NoVerification(Arc<CryptoProvider>);

impl ServerCertVerifier for NoVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// Turns a rustls/IO error from the TLS handshake into a categorised error.
pub fn handshake_error(host: &str, e: std::io::Error) -> Error {
    let detail = e
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<rustls::Error>())
        .map(|r| r.to_string())
        .unwrap_or_else(|| e.to_string());
    Error::tls(format!("TLS handshake with `{host}` failed: {detail}"))
}
