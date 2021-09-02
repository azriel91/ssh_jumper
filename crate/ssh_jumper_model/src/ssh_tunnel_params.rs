use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use crate::{HostAddress, HostSocketParams, JumpHostAuthParams};

/// When we use `0` as the local port to forward, the OS will choose a free
/// port.
const LOCAL_OS_CHOSEN_PORT: u16 = 0;

/// Parameters to create the SSH tunnel.
#[derive(Clone, Debug)]
pub struct SshTunnelParams<'tunnel> {
    /// Jump host address and port.
    pub jump_host: HostSocketParams<'tunnel>,
    /// SSH auth params for the jump host.
    pub jump_host_auth_params: JumpHostAuthParams<'tunnel>,
    /// Local socket to forward to the target host.
    pub local_socket: SocketAddr,
    /// Target host address and port.
    pub target_socket: HostSocketParams<'tunnel>,
}

impl<'tunnel> SshTunnelParams<'tunnel> {
    /// Returns new `SshTunnelParams`.
    ///
    /// The local socket IP is defaulted to `127.0.0.1`. Use the
    /// [`with_local_ip`][`Self::with_local_ip`] method if you would
    /// like to change this.
    ///
    /// The local socket port is defaulted to `0`, which means the operating
    /// system will allocate a port upon binding. Use the
    /// [`with_local_port`][`Self::with_local_port`] method if you would like to
    /// change this.
    pub fn new(
        jump_host: HostAddress<'tunnel>,
        jump_host_auth_params: JumpHostAuthParams<'tunnel>,
        target_socket: HostSocketParams<'tunnel>,
    ) -> Self {
        let local_socket = SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            LOCAL_OS_CHOSEN_PORT,
        );
        let jump_host_params: HostSocketParams = HostSocketParams {
            address: jump_host,
            port: 22,
        };

        SshTunnelParams {
            jump_host: jump_host_params,
            jump_host_auth_params,
            local_socket,
            target_socket,
        }
    }

    /// Sets the local IP to use.
    ///
    /// Useful if you are connecting over a VPN, and need to bind to the local
    /// IP for that network interface.
    pub fn with_local_ip(mut self, ip: IpAddr) -> Self {
        self.local_socket.set_ip(ip);
        self
    }

    /// Sets the local port to use.
    ///
    /// Useful if you want use a known port for forwarding.
    pub fn with_local_port(mut self, port: u16) -> Self {
        self.local_socket.set_port(port);
        self
    }

    /// Sets the jump host port to use for SSH.
    ///
    /// Useful if you do not want to use the default port for ssh.
    pub fn with_jump_host_port(mut self, port: u16) -> Self {
        self.jump_host.port = port;
        self
    }
}
