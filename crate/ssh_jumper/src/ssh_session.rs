use std::{
    net::TcpStream,
    ops::{Deref, DerefMut},
};

use async_ssh2_lite::AsyncSession;

/// SSH session that has been established.
pub struct SshSession(pub(crate) AsyncSession<TcpStream>);

impl Deref for SshSession {
    type Target = AsyncSession<TcpStream>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for SshSession {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
