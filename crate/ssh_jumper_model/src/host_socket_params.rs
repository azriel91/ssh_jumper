use std::fmt;

use crate::HostAddress;

/// Parameters to identify a host and port.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostSocketParams<'host> {
    /// Name or IP address of the host.
    pub address: HostAddress<'host>,
    /// Port to use.
    pub port: u16,
}

impl<'host> fmt::Display for HostSocketParams<'host> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}:{}", self.address, self.port)
    }
}

impl<'host> HostSocketParams<'host> {
    /// Returns an owned version of self.
    pub fn into_static(&self) -> HostSocketParams<'static> {
        HostSocketParams {
            address: self.address.into_static(),
            port: self.port,
        }
    }
}
