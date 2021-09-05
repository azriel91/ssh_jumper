use std::io;

#[derive(Debug)]
pub enum SshForwarderEnd {
    /// Failed to connect to local TCP listener.
    LocalConnectFail(io::Error),
    /// Local TCP stream reached EOF.
    LocalReadEof,
    /// IO error when writing data to SSH channel.
    ///
    /// This may happen due to any of:
    ///
    /// * SSH connection breaking, e.g. due to timeout or flakey connection.
    /// * Target host closing the connection, and how that propagates through
    ///   the SSH channel.
    LocalToChannelWriteErr(io::Error),
    /// IO error when reading from local TCP stream.
    LocalReadErr(io::Error),
    /// Read from SSH channel reached EOF.
    ChannelReadEof,
    /// IO error when writing data to local TCP stream.
    ///
    /// This happens when the local connection is closed when data is still
    /// being written.
    ChannelToLocalWriteErr(io::Error),
    /// IO error when reading from SSH channel.
    ChannelReadErr(io::Error),
}
