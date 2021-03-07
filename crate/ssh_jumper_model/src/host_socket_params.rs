use crate::HostAddress;

/// Parameters to identify a host and port.
#[derive(Clone, Debug, PartialEq)]
pub struct HostSocketParams<'host> {
    /// Name or IP address of the host.
    pub address: HostAddress<'host>,
    /// Port to use.
    pub port: u16,
}
