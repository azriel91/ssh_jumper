use std::{borrow::Cow, path::Path};

use crate::AuthMethod;

/// Parameters to authenticate with the jump host.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JumpHostAuthParams<'auth> {
    /// User to log in to the jump host as.
    pub user_name: Cow<'auth, str>,
    /// Authentication method and details.
    pub auth_method: AuthMethod<'auth>,
}

impl<'auth> JumpHostAuthParams<'auth> {
    /// Returns new [`JumpHostAuthParams`].
    ///
    /// The private key passphrase is defaulted to `None`.
    ///
    /// # Parameters:
    ///
    /// * `user_name`: Username to log into the jump host.
    /// * `private_key`: Path to the private key file.
    /// * `passphrase`: Passphrase to decrypt the private key.
    pub fn key_pair(
        user_name: Cow<'auth, str>,
        private_key: Cow<'auth, Path>,
        passphrase: Option<Cow<'auth, str>>,
    ) -> Self {
        Self {
            user_name,
            auth_method: AuthMethod::KeyPair {
                private_key,
                passphrase,
            },
        }
    }

    /// Returns new [`JumpHostAuthParams`].
    ///
    /// The private key passphrase is defaulted to `None`.
    ///
    /// # Parameters:
    ///
    /// * `user_name`: Username to log into the jump host.
    /// * `password`: Password to log in.
    pub fn password(user_name: Cow<'auth, str>, password: Cow<'auth, str>) -> Self {
        Self {
            user_name,
            auth_method: AuthMethod::Password { password },
        }
    }
}
