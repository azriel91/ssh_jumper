use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};

use async_io::Async;
use async_ssh2_lite::{AsyncChannel, AsyncSession, SessionConfiguration};
use async_std_resolver::resolver_from_system_conf;
use futures::{AsyncReadExt, AsyncWriteExt, FutureExt};
use ssh_jumper_model::{Error, HostAddress, HostSocketParams, JumpHostAuthParams, SshTunnelParams};

/// Forwards a local port to the target host through the jump host over SSH.
///
/// You are most likely interested in the following 3 methods:
///
/// * [`Self::open_tunnel`]: Opens an SSH session and creates a tunnel from a
///   local port to the target.
/// * [`Self::open_ssh_session`]: Opens an SSH session, but does not create the
///   tunnel.
/// * [`Self::open_direct_channel`]: Creates the tunnel using an existing SSH
///   session.
#[derive(Debug)]
pub struct SshJumper;

impl SshJumper {
    /// Opens an SSH tunnel.
    pub async fn open_tunnel(ssh_tunnel_params: &SshTunnelParams<'_>) -> Result<SocketAddr, Error> {
        let SshTunnelParams {
            jump_host,
            jump_host_auth_params,
            local_socket,
            target_socket,
        } = ssh_tunnel_params;
        let ssh_session = Self::open_ssh_session(jump_host, jump_host_auth_params).await?;
        let local_socket_addr =
            Self::open_direct_channel(&ssh_session, *local_socket, target_socket).await?;

        Ok(local_socket_addr)
    }

    pub async fn open_ssh_session(
        jump_host_addr: &HostAddress<'_>,
        jump_host_auth_params: &JumpHostAuthParams<'_>,
    ) -> Result<AsyncSession<TcpStream>, Error> {
        // See https://github.com/bk-rs/async-ssh2-lite/blob/1b88c9cb64553ab395596a4368fc30e8e2e341c4/demos/smol/src/remote_port_forwarding.rs
        // but we use `channel_direct_tcpip` for local forwarding

        let jump_host_user_name = &jump_host_auth_params.user_name;
        let jump_host_public_key = None;
        let jump_host_private_key = &jump_host_auth_params.private_key;
        let jump_host_private_key_passphrase = jump_host_auth_params.passphrase.as_deref();

        let jump_host_ip = match jump_host_addr {
            HostAddress::IpAddr(ip_addr) => *ip_addr,
            HostAddress::HostName(jump_host_addr) => Self::resolve_ip(&jump_host_addr).await?,
        };
        let stream = Async::<TcpStream>::connect(SocketAddr::from((jump_host_ip, 22)))
            .await
            .map_err(|io_error| Error::JumpHostConnectFail {
                jump_host_addr: jump_host_addr.into_static(),
                io_error,
            })?;

        let mut session_configuration = SessionConfiguration::new();
        session_configuration.set_compress(true);
        let mut session = AsyncSession::new(stream, Some(session_configuration))
            .map_err(Error::AsyncSessionInitialize)?;

        session.handshake().await.map_err(Error::SshHandshakeFail)?;
        session
            .userauth_pubkey_file(
                jump_host_user_name,
                jump_host_public_key,
                jump_host_private_key,
                jump_host_private_key_passphrase,
            )
            .await
            .map_err(Error::SshUserAuthFail)?;

        if !session.authenticated() {
            return Err(session
                .last_error()
                .map(Error::SshUserAuthError)
                .unwrap_or(Error::SshUserAuthUnknownError));
        }

        Ok(session)
    }

    pub async fn open_direct_channel(
        ssh_session: &AsyncSession<TcpStream>,
        local_socket: SocketAddr,
        target_socket: &HostSocketParams<'_>,
    ) -> Result<SocketAddr, Error> {
        let target_host_address = target_socket.address.to_string();
        let target_host_address = target_host_address.as_str();
        let target_port = target_socket.port;
        let source = None;

        let async_channel = ssh_session
            .channel_direct_tcpip(target_host_address, target_port, source)
            .await
            .map_err(Error::SshTunnelOpenFail)?;

        Self::spawn_channel_streamers(local_socket, async_channel).await
    }

    // https://github.com/bk-rs/async-ssh2-lite/blob/master/demos/smol/src/proxy_jump.rs
    async fn spawn_channel_streamers<'tunnel>(
        local_socket: SocketAddr,
        mut jump_host_channel: AsyncChannel<TcpStream>,
    ) -> Result<SocketAddr, Error> {
        let local_socket_addr = TcpListener::bind(local_socket)
            .map_err(|io_error| Error::LocalSocketBind {
                local_socket,
                io_error,
            })?
            .local_addr()
            .map_err(|io_error| Error::LocalSocketAddr {
                local_socket,
                io_error,
            })?;
        let local_socket_listener = Async::<TcpListener>::bind(local_socket_addr)
            .map_err(Error::SshTunnelListenerCreate)?;

        let spawn_join_handle = tokio::task::spawn(async move {
            let _detached_task = tokio::task::spawn(async move {
                let mut buf_jump_host_channel = vec![0; 2048];
                let mut buf_forward_stream_r = vec![0; 2048];

                let (mut forward_stream_r, _) = local_socket_listener.accept().await?;

                loop {
                    futures::select! {
                        ret_forward_stream_r = forward_stream_r.read(&mut buf_forward_stream_r).fuse() => match ret_forward_stream_r {
                            Ok(n) if n == 0 => {
                                break
                            },
                            Ok(n) => {
                                jump_host_channel.write(&buf_forward_stream_r[..n]).await.map(|_| ()).map_err(|err| {
                                    err
                                })?
                            },
                            Err(err) =>  {
                                return Err(err);
                            }
                        },
                        ret_jump_host_channel = jump_host_channel.read(&mut buf_jump_host_channel).fuse() => match ret_jump_host_channel {
                            Ok(n) if n == 0 => {
                                break
                            },
                            Ok(n) => {
                                forward_stream_r.write(&buf_jump_host_channel[..n]).await.map(|_| ()).map_err(|err| {
                                    err
                                })?
                            },
                            Err(err) => {
                                return Err(err);
                            }
                        },
                    }
                }

                // sender_with_forward.send("done_with_forward").await.unwrap();

                Ok(())
            });
        });

        spawn_join_handle
            .await
            .map_err(Error::SshStreamerSpawnFail)?;

        Ok(local_socket_addr)
    }

    async fn resolve_ip<'tunnel>(jump_host_addr: &str) -> Result<IpAddr, Error> {
        let resolver = resolver_from_system_conf()
            .await
            .map_err(Error::DnsResolverCreate)?;

        let mut lookup_addr = String::with_capacity(jump_host_addr.len() + 1);
        lookup_addr.push_str(jump_host_addr);
        lookup_addr.push('.');
        let response = resolver
            .lookup_ip(lookup_addr)
            .await
            .map_err(Error::DnsResolverLookup)?;
        if let Some(host_ip) = response.iter().next() {
            Ok(host_ip)
        } else {
            Err(Error::JumpHostIpResolutionFail {
                jump_host_addr: jump_host_addr.to_string(),
            })
        }
    }
}
