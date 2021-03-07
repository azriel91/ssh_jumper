use std::{borrow::Cow, fmt, io, net::SocketAddr};

use crate::HostAddress;

#[derive(Debug)]
pub enum Error<'tunnel> {
    JumpHostConnectFail {
        jump_host_addr: HostAddress<'tunnel>,
        io_error: io::Error,
    },
    AsyncSessionInitialize(io::Error),
    DnsResolverCreate(async_std_resolver::ResolveError),
    DnsResolverLookup(async_std_resolver::ResolveError),
    JumpHostIpResolutionFail {
        jump_host_addr: Cow<'tunnel, str>,
    },
    LocalSocketAddr {
        local_socket: SocketAddr,
        io_error: io::Error,
    },
    LocalSocketBind {
        local_socket: SocketAddr,
        io_error: io::Error,
    },
    SshHandshakeFail(io::Error),
    SshUserAuthFail(io::Error),
    SshUserAuthError(async_ssh2_lite::ssh2::Error),
    SshUserAuthUnknownError,
    SshTunnelOpenFail(io::Error),
    SshTunnelListenerCreate(io::Error),
    SshTunnelStreamCreate(io::Error),
    SshStreamerSpawnFail(tokio::task::JoinError),
}

impl<'tunnel> fmt::Display for Error<'tunnel> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::JumpHostConnectFail { jump_host_addr, .. } => {
                write!(f, "Failed to connect to jump host: `{}`.", jump_host_addr)
            }
            Self::AsyncSessionInitialize(..) => {
                write!(f, "Failed to initialize SSH session with jump host.")
            }
            Self::DnsResolverCreate(..) => write!(f, "Failed to construct DNS resolver."),
            Self::DnsResolverLookup(resolve_error) => {
                write!(f, "Failed to lookup IP for jump host: `{}`.", resolve_error)
            }
            Self::JumpHostIpResolutionFail { jump_host_addr } => {
                write!(
                    f,
                    "Failed to find IPv4 address for jump host: `{}`.",
                    jump_host_addr
                )
            }
            Self::LocalSocketAddr { local_socket, .. } => write!(
                f,
                "Failed to retrieve socket address after binding to: {}.",
                local_socket
            ),
            Self::LocalSocketBind { local_socket, .. } => {
                write!(f, "Failed to bind to local socket: {}.", local_socket)
            }
            Self::SshHandshakeFail(..) => write!(f, "SSH handshake with jump host failed."),
            Self::SshUserAuthFail(..) => write!(f, "SSH user auth with jump host failed."),
            Self::SshUserAuthError(..) => write!(f, "SSH user auth with jump host failed.",),
            Self::SshUserAuthUnknownError => {
                write!(f, "SSH user auth with jump host failed with unknown cause.")
            }
            Self::SshTunnelOpenFail(..) => write!(f, "Failed to open SSH tunnel."),
            Self::SshTunnelListenerCreate(..) => write!(f, "Failed to spawn SSH tunnel listener"),
            Self::SshTunnelStreamCreate(..) => write!(f, "Failed to spawn SSH tunnel stream."),
            Self::SshStreamerSpawnFail(..) => write!(f, "Failed to join SSH tunnel streamer task."),
        }
    }
}

impl<'tunnel> std::error::Error for Error<'tunnel> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::JumpHostConnectFail { io_error, .. } => Some(io_error),
            Self::AsyncSessionInitialize(io_error) => Some(io_error),
            Self::DnsResolverCreate(resolve_error) => Some(resolve_error),
            Self::DnsResolverLookup(resolve_error) => Some(resolve_error),
            Self::JumpHostIpResolutionFail { .. } => None,
            Self::LocalSocketAddr { io_error, .. } => Some(io_error),
            Self::LocalSocketBind { io_error, .. } => Some(io_error),
            Self::SshHandshakeFail(io_error) => Some(io_error),
            Self::SshUserAuthFail(io_error) => Some(io_error),
            Self::SshUserAuthError(ssh2_error) => Some(ssh2_error),
            Self::SshUserAuthUnknownError => None,
            Self::SshTunnelOpenFail(io_error) => Some(io_error),
            Self::SshTunnelListenerCreate(io_error) => Some(io_error),
            Self::SshTunnelStreamCreate(io_error) => Some(io_error),
            Self::SshStreamerSpawnFail(join_error) => Some(join_error),
        }
    }
}
