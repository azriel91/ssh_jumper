# 🌐💨 SSH Jumper

Async SSH tunnel through a jump host.

```rust
use std::borrow::Cow;
use ssh_jumper::{
    model::{HostAddress, HostSocketParams, JumpHostAuthParams, SshTunnelParams},
    SshJumper
};

// Similar to running:
// ssh -i ~/.ssh/id_rsa -L 1234:target_host:8080 my_user@bastion.com
let local_socket_addr = {
    let jump_host = HostAddress::HostName(Cow::Borrowed("bastion.com"));
    let jump_host_auth_params = JumpHostAuthParams::new(
        Cow::Borrowed("my_user"),
        Cow::Borrowed(Path::new("~/.ssh/id_rsa")),
    );
    let target_socket = HostSocketParams {
        address: HostAddress::HostName(Cow::Borrowed("target_host")),
        port: 8080,
    };
    let ssh_params =
        SshTunnelParams::new(jump_host, jump_host_auth_params, target_socket)
            // Optional: OS will allocate a port if this is left out
            .with_local_port(1234);

    SshJumper::open_tunnel(&ssh_params).await?
};

// Now you can send traffic to `local_socket_addr`, and it will go to `target_host`.
```

## License

Licensed under either of

* Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or https://www.apache.org/licenses/LICENSE-2.0)
* MIT license ([LICENSE-MIT](LICENSE-MIT) or https://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
