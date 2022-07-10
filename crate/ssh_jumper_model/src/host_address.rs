use std::{borrow::Cow, fmt, net::IpAddr};

/// Parameters to identify a host and port.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HostAddress<'host> {
    /// IP Address such as `IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))`.
    IpAddr(IpAddr),
    /// Host name string, which needs to be resolved to an IP address.
    HostName(Cow<'host, str>),
}

impl<'host> fmt::Display for HostAddress<'host> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::IpAddr(ip_addr) => ip_addr.fmt(f),
            Self::HostName(host_name) => host_name.fmt(f),
        }
    }
}

impl<'host> HostAddress<'host> {
    /// Returns an owned version of self.
    pub fn into_static(&self) -> HostAddress<'static> {
        match self {
            Self::IpAddr(ip_addr) => HostAddress::IpAddr(*ip_addr),
            Self::HostName(host_name) => {
                HostAddress::HostName(Cow::Owned(host_name.clone().into_owned()))
            }
        }
    }
}
