use std::{io::Cursor, sync::Arc, time::Duration};

use fxhash::FxHashSet;
use hickory_client::client::Client;
use hickory_proto::{
    h3::H3ClientStream,
    quic::QuicClientStream,
    runtime::TokioRuntimeProvider,
    udp::{UdpClientStream, UdpSocket},
};
use hickory_server::{Server, server::RequestHandler};
use rustls::{
    crypto::ring,
    sign::{CertifiedKey, SingleCertAndKey},
};
use url::Url;

#[derive(PartialEq, Eq)]
enum UpstreamKind {
    Udp,
    H3,
    Quic,
}

impl std::str::FromStr for UpstreamKind {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "udp" => Ok(UpstreamKind::Udp),
            "h3" => Ok(UpstreamKind::H3),
            "quic" => Ok(UpstreamKind::Quic),
            _ => Err(anyhow::anyhow!("Invalid upstream kind: {}", s)),
        }
    }
}

pub struct Configure {
    upstream_kind: UpstreamKind,
    upstream_addr: String,
    upstream_uri: Option<String>,
    bind_udp: Option<String>,
    bind_h3: Option<String>,
    bind_quic: Option<String>,
    bind_timeout: Duration,
    bind_hostname: Option<String>,
    bind_cert: Option<String>,
    bind_private_key: Option<String>,
    blocklist: String,
}

impl Configure {
    fn get_env(name: &str) -> anyhow::Result<String> {
        Self::get_env_optional(name)?
            .ok_or_else(|| anyhow::anyhow!("Environment variable {name} is not set"))
    }
    fn get_env_optional(name: &str) -> anyhow::Result<Option<String>> {
        Ok(match std::env::var(name) {
            Ok(e) => Some(e),
            Err(std::env::VarError::NotPresent) => None,
            Err(e) => anyhow::bail!("{e}"),
        })
    }
    fn get_env_bool_with_default(name: &str, default: bool) -> anyhow::Result<bool> {
        if let Some(e) = Self::get_env_optional(name)?
            .map(|s| s.parse())
            .transpose()?
        {
            Ok(e)
        } else {
            Ok(default)
        }
    }
    pub fn new() -> anyhow::Result<Self> {
        Ok(Self {
            upstream_kind: Self::get_env_optional("UPSTREAM_KIND")?
                .map(|s| s.parse())
                .transpose()?
                .unwrap_or(UpstreamKind::Udp),
            upstream_addr: Self::get_env("UPSTREAM_ADDR")?,
            upstream_uri: Self::get_env_optional("UPSTREAM_URI")?,
            bind_udp: if Self::get_env_bool_with_default("BIND_UDP", true)? {
                Some(Self::get_env("BIND_UDP_ADDR")?)
            } else {
                None
            },
            bind_h3: if Self::get_env_bool_with_default("BIND_H3", false)? {
                Some(Self::get_env("BIND_H3_ADDR")?)
            } else {
                None
            },
            bind_quic: if Self::get_env_bool_with_default("BIND_QUIC", false)? {
                Some(Self::get_env("BIND_QUIC_ADDR")?)
            } else {
                None
            },
            bind_timeout: Self::get_env_optional("BIND_TIMEOUT")?
                .map(|s| anyhow::Ok(Duration::from_secs(s.parse()?)))
                .transpose()?
                .unwrap_or(Duration::from_millis(500)),
            bind_hostname: Self::get_env_optional("BIND_HOSTNAME")?,
            bind_cert: Self::get_env_optional("BIND_CERT_PATH")?,
            bind_private_key: Self::get_env_optional("BIND_PRIVATE_KEY_PATH")?,
            blocklist: Self::get_env_optional("BLOCKLIST_PATH")?
                .unwrap_or("default.blocklist".to_string()),
        })
    }
    pub async fn build_blocklist(&self) -> anyhow::Result<FxHashSet<String>> {
        let mut set = FxHashSet::default();
        for line in tokio::fs::read_to_string(&self.blocklist).await?.lines() {
            let mut line = line.trim().to_string();
            if !line.ends_with(".") {
                line.push('.');
            }
            set.insert(line);
        }
        Ok(set)
    }
    async fn read_cert(&self) -> anyhow::Result<CertifiedKey> {
        let cert_chain_pem_file = self
            .bind_cert
            .clone()
            .ok_or(anyhow::anyhow!("BIND_CERT_PATH is not set"))?;
        let private_key_pem_file = self
            .bind_private_key
            .clone()
            .ok_or(anyhow::anyhow!("BIND_PRIVATE_KEY_PATH is not set"))?;
        let cert_chain_pem = tokio::fs::read_to_string(cert_chain_pem_file).await?;
        let private_key_pem = tokio::fs::read_to_string(private_key_pem_file).await?;
        let mut cert_cursor = Cursor::new(cert_chain_pem.as_bytes());
        let mut chain = vec![];
        for c in rustls_pemfile::certs(&mut cert_cursor) {
            chain.push(c?);
        }
        if chain.is_empty() {
            anyhow::bail!("no certificates found in cert_chain_pem");
        }

        let mut key_cursor = Cursor::new(private_key_pem.as_bytes());
        let key = rustls_pemfile::private_key(&mut key_cursor)?
            .ok_or(anyhow::anyhow!("no private key found in private_key_pem"))?;
        Ok(CertifiedKey::from_der(
            chain,
            key,
            &ring::default_provider(),
        )?)
    }
    pub async fn register_sockets<T>(&self, server: &mut Server<T>) -> anyhow::Result<()>
    where
        T: RequestHandler,
    {
        if let Some(addr) = &self.bind_udp {
            log::info!("Binding UDP socket to: {}", addr);
            let socket = UdpSocket::bind(addr.parse()?).await?;
            server.register_socket(socket);
            log::info!("Bound UDP socket to: {}", addr);
        } else {
            log::info!("Not binding UDP socket");
        }
        if let Some(addr) = &self.bind_h3 {
            log::info!("Binding H3 socket to: {}", addr);
            let socket = UdpSocket::bind(addr.parse()?).await?;
            server.register_h3_listener(
                socket,
                self.bind_timeout,
                Arc::new(SingleCertAndKey::from(Arc::new(self.read_cert().await?))),
                self.bind_hostname.clone(),
            )?;
            log::info!("Bound H3 socket to: {}", addr);
        } else {
            log::info!("Not binding H3 socket");
        }
        if let Some(addr) = &self.bind_quic {
            log::info!("Binding QUIC socket to: {}", addr);
            let socket = UdpSocket::bind(addr.parse()?).await?;
            server.register_quic_listener(
                socket,
                self.bind_timeout,
                Arc::new(SingleCertAndKey::from(Arc::new(self.read_cert().await?))),
                self.bind_hostname.clone(),
            )?;
            log::info!("Bound QUIC socket to: {}", addr);
        } else {
            log::info!("Not binding QUIC socket");
        }
        Ok(())
    }

    pub async fn spawn_upstream(
        &self,
    ) -> anyhow::Result<(
        Client,
        tokio::task::JoinHandle<Result<(), hickory_proto::ProtoError>>,
    )> {
        Ok(match self.upstream_kind {
            UpstreamKind::Udp => {
                let conn = UdpClientStream::builder(
                    self.upstream_addr.parse()?,
                    TokioRuntimeProvider::new(),
                )
                .build();
                let (upstream, background) = Client::connect(conn).await?;
                log::info!("Connected to UDP upstream: {}", self.upstream_addr);
                (upstream, tokio::spawn(background))
            }
            UpstreamKind::H3 => {
                let uri = Url::parse(
                    &self
                        .upstream_uri
                        .clone()
                        .ok_or(anyhow::anyhow!("UPSTREAM_URI must be set for H3 upstream"))?,
                )?;
                if uri.scheme() != "h3" {
                    anyhow::bail!("UPSTREAM_URI must use h3 scheme")
                }
                let (host, path) = (
                    uri.host_str().ok_or(anyhow::anyhow!("Invalid host"))?,
                    uri.path(),
                );
                let conn = H3ClientStream::builder().build(
                    self.upstream_addr.parse()?,
                    host.into(),
                    path.into(),
                );
                let (upstream, background) = Client::connect(conn).await?;
                log::info!("Connected to H3 upstream: {}", self.upstream_addr);
                (upstream, tokio::spawn(background))
            }
            UpstreamKind::Quic => {
                let uri = Url::parse(&self.upstream_uri.clone().ok_or(anyhow::anyhow!(
                    "UPSTREAM_URI must be set for QUIC upstream"
                ))?)?;
                if uri.scheme() != "quic" {
                    anyhow::bail!("UPSTREAM_URI must use quic scheme")
                }
                let host = uri.host_str().ok_or(anyhow::anyhow!("Invalid host"))?;
                let conn =
                    QuicClientStream::builder().build(self.upstream_addr.parse()?, host.into());
                let (upstream, background) = Client::connect(conn).await?;
                log::info!("Connected to QUIC upstream: {}", self.upstream_addr);
                (upstream, tokio::spawn(background))
            }
        })
    }
}
