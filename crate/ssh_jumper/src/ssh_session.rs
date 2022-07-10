use std::{
    net::TcpStream,
    ops::{Deref, DerefMut},
};

use async_io::Async;
use async_ssh2_lite::AsyncSession;

/// SSH session that has been established.
pub struct SshSession(pub(crate) AsyncSession<Async<TcpStream>>);

impl Deref for SshSession {
    type Target = AsyncSession<Async<TcpStream>>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for SshSession {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
