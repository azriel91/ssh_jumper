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
            Self::JumpHostConnectFail {
                jump_host_addr,
                io_error,
            } => write!(
                f,
                "Failed to connect to Jump Host: {}, IO error: {}",
                jump_host_addr, io_error
            ),
            Self::AsyncSessionInitialize(io_error) => write!(
                f,
                "Failed to initialize SSH session with jump host, IO error: {}",
                io_error,
            ),
            Self::DnsResolverCreate(resolve_error) => {
                write!(
                    f,
                    "Failed to construct DNS resolver. error: {}",
                    resolve_error
                )
            }
            Self::DnsResolverLookup(resolve_error) => {
                write!(f, "Failed to lookup IP for Jump Host: {}", resolve_error)
            }
            Self::JumpHostIpResolutionFail { jump_host_addr } => {
                write!(
                    f,
                    "Failed to find IPv4 address for Jump Host: {}",
                    jump_host_addr
                )
            }
            Self::LocalSocketAddr {
                local_socket,
                io_error,
            } => write!(
                f,
                "Failed to retrieve socket address after binding to: {}, error: {}",
                local_socket, io_error
            ),
            Self::LocalSocketBind {
                local_socket,
                io_error,
            } => write!(
                f,
                "Failed to bind to local socket: {}, error: {}",
                local_socket, io_error
            ),
            Self::SshHandshakeFail(io_error) => write!(
                f,
                "SSH handshake with jump host failed, IO error: {}",
                io_error,
            ),
            Self::SshUserAuthFail(io_error) => write!(
                f,
                "SSH user auth with jump host failed, IO error: {}",
                io_error,
            ),
            Self::SshUserAuthError(ssh2_error) => write!(
                f,
                "SSH user auth with jump host failed, SSH2 error: {}",
                ssh2_error,
            ),
            Self::SshUserAuthUnknownError => {
                write!(f, "SSH user auth with jump host failed with unknown cause.",)
            }
            Self::SshTunnelOpenFail(io_error) => {
                write!(f, "Failed to open SSH tunnel, IO error: {}", io_error)
            }
            Self::SshTunnelListenerCreate(io_error) => write!(
                f,
                "Failed to spawn SSH tunnel listener, IO error: {}",
                io_error
            ),
            Self::SshTunnelStreamCreate(io_error) => write!(
                f,
                "Failed to spawn SSH tunnel stream, IO error: {}",
                io_error
            ),
            Self::SshStreamerSpawnFail(join_error) => {
                write!(f, "Failed to join SSH tunnel streamer task: {}", join_error)
            }
        }
    }
}

impl<'tunnel> std::error::Error for Error<'tunnel> {}
