use std::{borrow::Cow, path::Path};

/// Authentication method and details.
#[derive(Clone, Debug, PartialEq)]
pub enum AuthMethod<'auth> {
    /// Use a private/public key pair for authentication.
    KeyPair {
        /// Private key to use.
        private_key: Cow<'auth, Path>,
        /// Passphrase for the private key.
        passphrase: Option<Cow<'auth, str>>,
    },
    Password {
        /// Password to use.
        password: Cow<'auth, str>,
    },
}
