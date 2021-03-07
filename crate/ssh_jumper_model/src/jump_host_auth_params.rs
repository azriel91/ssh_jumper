use std::{borrow::Cow, path::Path};

/// Parameters to authenticate with the jump host.
#[derive(Clone, Debug, PartialEq)]
pub struct JumpHostAuthParams<'auth> {
    /// User to log in to the jump host as.
    pub user_name: Cow<'auth, str>,
    /// Private key to use.
    pub private_key: Cow<'auth, Path>,
    /// Passphrase for the private key.
    pub passphrase: Option<Cow<'auth, str>>,
}

impl<'auth> JumpHostAuthParams<'auth> {
    /// Returns new [`JumpHostAuthParams`].
    ///
    /// The private key passphrase is defaulted to `None`.
    pub fn new(user_name: Cow<'auth, str>, private_key: Cow<'auth, Path>) -> Self {
        Self {
            user_name,
            private_key,
            passphrase: None,
        }
    }

    /// Sets the passphrase to decrypt the private key.
    pub fn with_passphrase(mut self, passphrase: Cow<'auth, str>) -> Self {
        self.passphrase = Some(passphrase);
        self
    }
}
