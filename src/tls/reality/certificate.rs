//! 成熟 DER 编码、REALITY 证书认证与真实 TLS 签名密钥分别持有。
use std::{fmt, io, sync::Arc};

use aws_lc_rs::{
    hmac,
    rand::SystemRandom,
    signature::{Ed25519KeyPair, KeyPair as _, ML_DSA_65_SIGNING, PqdsaKeyPair},
};
use rcgen::{CertificateParams, CustomExtension, DistinguishedName, RemoteKeyPair, SerialNumber};
use rustls::{
    Error,
    pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer},
    server::reality::ResolvesCertificate,
    sign::{CertifiedKey, SigningKey},
};

fn invalid() -> io::Error {
    io::Error::other("REALITY 证书准备失败")
}

// 不持有 DER 远程私钥，也不调用 rcgen RemoteKeyPair 的私钥序列化接口。
struct CertificateSignature {
    public: [u8; 32],
    signature: Vec<u8>,
}
impl RemoteKeyPair for CertificateSignature {
    fn public_key(&self) -> &[u8] {
        &self.public
    }
    fn sign(&self, _: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        Ok(self.signature.clone())
    }
    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        &rcgen::PKCS_ED25519
    }
}

pub(crate) struct Identity {
    public: [u8; 32],
    signing: Arc<dyn SigningKey>,
    mldsa: Option<PqdsaKeyPair>,
}
impl Identity {
    pub(crate) fn new(seed: Option<&[u8; 32]>) -> io::Result<Self> {
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).map_err(|_| invalid())?;
        let ed = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).map_err(|_| invalid())?;
        let public = ed.public_key().as_ref().try_into().map_err(|_| invalid())?;
        let private = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pkcs8.as_ref().to_vec()));
        let signing =
            rustls::crypto::aws_lc_rs::sign::any_supported_type(&private).map_err(|_| invalid())?;
        let mldsa = seed
            .map(|seed| PqdsaKeyPair::from_seed(&ML_DSA_65_SIGNING, seed))
            .transpose()
            .map_err(|_| invalid())?;
        Ok(Self {
            public,
            signing,
            mldsa,
        })
    }

    pub(crate) fn resolver(self: &Arc<Self>, key: [u8; 32], raw_ch: Vec<u8>) -> Resolver {
        Resolver {
            identity: self.clone(),
            key,
            raw_ch,
        }
    }

    fn certificate(
        &self,
        key: &[u8; 32],
        extension: Option<Vec<u8>>,
    ) -> io::Result<Arc<CertifiedKey>> {
        let signature = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA512, key), &self.public);
        let remote = rcgen::KeyPair::from_remote(Box::new(CertificateSignature {
            public: self.public,
            signature: signature.as_ref().to_vec(),
        }))
        .map_err(|_| invalid())?;
        // 无 SAN、usage、CA 或 AKI 等自动扩展，ML-DSA 才能是首扩展。
        let mut params = CertificateParams::default();
        params.serial_number = Some(SerialNumber::from(1u64));
        params.distinguished_name = DistinguishedName::new();
        if let Some(signature) = extension {
            params
                .custom_extensions
                .push(CustomExtension::from_oid_content(&[0, 0], signature));
        }
        let certificate = params.self_signed(&remote).map_err(|_| invalid())?;
        let certified = CertifiedKey::new(vec![certificate.der().clone()], self.signing.clone());
        certified.keys_match().map_err(|_| invalid())?;
        Ok(Arc::new(certified))
    }
}

pub(crate) struct Resolver {
    identity: Arc<Identity>,
    key: [u8; 32],
    raw_ch: Vec<u8>,
}
impl fmt::Debug for Resolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RealityCertificateResolver([REDACTED])")
    }
}
impl Resolver {
    pub(crate) fn initial(&self) -> io::Result<Arc<CertifiedKey>> {
        self.identity.certificate(&self.key, None)
    }
}
impl ResolvesCertificate for Resolver {
    fn resolve(&self, final_raw_sh: &[u8]) -> Result<Arc<CertifiedKey>, Error> {
        let extension = self
            .identity
            .mldsa
            .as_ref()
            .map(|mldsa| {
                let mut mac =
                    hmac::Context::with_key(&hmac::Key::new(hmac::HMAC_SHA512, &self.key));
                mac.update(&self.identity.public);
                mac.update(&self.raw_ch);
                mac.update(final_raw_sh);
                let message = mac.sign();
                let mut signature = vec![0; ML_DSA_65_SIGNING.signature_len()];
                let len = mldsa
                    .sign(message.as_ref(), &mut signature)
                    .map_err(|_| invalid())?;
                if len != 3309 {
                    return Err(invalid());
                }
                Ok(signature)
            })
            .transpose()
            .map_err(|_| Error::General("REALITY 证书构造失败".into()))?;
        self.identity
            .certificate(&self.key, extension)
            .map_err(|_| Error::General("REALITY 证书构造失败".into()))
    }
}
