//! Async SSH tunnel through a jump host.
//!
//! # Examples
//!
//! ```rust,ignore
//! use std::borrow::Cow;
//! use ssh_jumper::{
//!     model::{HostAddress, HostSocketParams, JumpHostAuthParams, SshTunnelParams},
//!     SshJumper
//! };
//!
//! // Similar to running:
//! // ssh -i ~/.ssh/id_rsa -L 1234:target_host:8080 my_user@bastion.com
//! let local_socket_addr = {
//!     let jump_host = HostAddress::HostName(Cow::Borrowed("bastion.com"));
//!     let jump_host_auth_params = JumpHostAuthParams::new(
//!         Cow::Borrowed("my_user"),
//!         Cow::Borrowed(Path::new("~/.ssh/id_rsa")),
//!     );
//!     let target_socket = HostSocketParams {
//!         address: HostAddress::HostName(Cow::Borrowed("target_host")),
//!         port: 8080,
//!     };
//!     let ssh_params =
//!         SshTunnelParams::new(jump_host, jump_host_auth_params, target_socket)
//!             // Optional: OS will allocate a port if this is left out
//!             .with_local_port(1234);
//!
//!     SshJumper::open_tunnel(&ssh_params).await?
//! };
//!
//! // Now you can send traffic to `local_socket_addr`, and it will go to `target_host`.
//! ```

pub use ssh_jumper_model as model;

pub use crate::ssh_jumper::SshJumper;

mod ssh_jumper;
