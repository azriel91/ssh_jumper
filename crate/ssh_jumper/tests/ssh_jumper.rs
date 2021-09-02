use std::{
    borrow::Cow,
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
};

use ssh_jumper::{
    model::{HostAddress, HostSocketParams, JumpHostAuthParams, SshTunnelParams},
    SshJumper,
};
use tokio::{
    runtime,
    sync::{mpsc, oneshot},
};

#[test]
fn ssh_jumper_connect() -> Result<(), Box<dyn std::error::Error>> {
    let rt = runtime::Builder::new_current_thread().build()?;
    let local_port = 1234;
    let jump_host_ssh_port = 2222;
    let target_port = 8080;

    rt.block_on::<_>(async move {
        // Forward port 1234 to 8080 through SSH server at 2222
        //
        // ssh -i ~/.ssh/id_rsa -L 1234:127.0.0.1:8080 my_user@127.0.0.1:2222

        // spawn server thread
        let (server_ready_tx, server_ready_rx) = oneshot::channel::<()>();
        let (client_done_tx, client_done_rx) = mpsc::channel::<()>(1);

        let server_thread_handler = std::thread::spawn(move || {
            let _ =
                ssh_server::open_server_socket(jump_host_ssh_port, server_ready_tx, client_done_rx);
        });

        let _ = server_ready_rx.await?;

        match ssh_connection_open(local_port, jump_host_ssh_port, target_port).await {
            Ok((local_socket_addr, _ssh_error_rx)) => {
                println!("connected: {}", local_socket_addr);

                client_done_tx
                    .send(())
                    .await
                    .expect("Failed to notify server that client is done.");
                server_thread_handler.join().unwrap();
            }
            Err(e) => {
                server_thread_handler.join().unwrap();
                panic!("Failed to open SSH connection: {}", e);
            }
        }

        Result::<_, Box<dyn std::error::Error>>::Ok(())
    })?;

    Ok(())
}

async fn ssh_connection_open(
    local_port: u16,
    jump_host_ssh_port: u16,
    target_port: u16,
) -> Result<(SocketAddr, oneshot::Receiver<io::Error>), ssh_jumper::model::Error> {
    let localhost_addr = HostAddress::IpAddr(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));

    let jump_host = localhost_addr.clone();
    let jump_host_auth_params =
        JumpHostAuthParams::password(Cow::Borrowed("my_user"), Cow::Borrowed("my_password"));
    let target_socket = HostSocketParams {
        address: localhost_addr,
        port: target_port,
    };
    let ssh_params = SshTunnelParams::new(jump_host, jump_host_auth_params, target_socket)
        .with_local_port(local_port)
        .with_jump_host_port(jump_host_ssh_port);

    SshJumper::open_tunnel(&ssh_params).await
}

// See https://github.com/tomasol/libssh-sys-dylib/blob/master/tests/smoke_test.rs
mod ssh_server {
    use std::{
        convert::TryInto,
        ffi::{CStr, CString},
        fs::File,
        os::raw::c_int,
    };

    use libssh_sys_dylib::*;
    use tokio::sync::{mpsc::Receiver, oneshot::Sender};

    type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

    pub fn open_server_socket(
        jump_host_ssh_port: u16,
        server_ready_tx: Sender<()>,
        mut client_done_rx: Receiver<()>,
    ) -> Result<()> {
        let ssh_bind: ssh_bind = unsafe { ssh_bind_new() };
        assert!(ssh_bind.is_null() == false, "Cannot create bind");

        set_bind_option(
            ssh_bind,
            ssh_bind_options_e_SSH_BIND_OPTIONS_BINDADDR,
            "127.0.0.1",
        );
        set_bind_option(
            ssh_bind,
            ssh_bind_options_e_SSH_BIND_OPTIONS_BINDPORT_STR,
            &format!("{}", jump_host_ssh_port),
        );

        set_bind_option(
            ssh_bind,
            ssh_bind_options_e_SSH_BIND_OPTIONS_RSAKEY,
            check_file_exists("tests/assets/id_rsa")?,
        );
        set_bind_option(
            ssh_bind,
            ssh_bind_options_e_SSH_BIND_OPTIONS_DSAKEY,
            check_file_exists("tests/assets/id_dsa")?,
        );

        // listen
        let res = unsafe { ssh_bind_listen(ssh_bind) };

        assert!(res == SSH_OK as c_int, "Error while ssh_bind_listen");

        let session: ssh_session = unsafe { ssh_new() };
        assert!(session.is_null() == false, "Server session is null");

        if server_ready_tx.send(()).is_ok() {
            println!("Calling ssh_bind_accept");
            // accept will block until connected
            let res = unsafe { ssh_bind_accept(ssh_bind, session) };
            assert!(res == SSH_OK as c_int, "Error while ssh_bind_accept");
            println!("Calling ssh_handle_key_exchange");
            let res = unsafe { ssh_handle_key_exchange(session) };
            assert!(
                res == SSH_OK as c_int,
                "Error while ssh_handle_key_exchange"
            );

            // handle auth
            let auth = authenticate(session);
            assert!(auth, "Auth error");

            // wait for requesting channel, shell, pty
            let ch = wait_for_channel(session);
            assert!(ch.is_some(), "Channel not opened");

            println!("It works!");

            client_done_rx.blocking_recv();
        }

        unsafe {
            ssh_disconnect(session);
            ssh_free(session);
            ssh_bind_free(ssh_bind);
            ssh_finalize();
        }

        Ok(())
    }

    fn check_username_password(username: &CStr, password: &CStr) -> bool {
        println!("User {:?} wants to auth with pass {:?}", username, password);
        let username_test: &CStr = &CString::new("my_user").unwrap();
        let password_test: &CStr = &CString::new("my_password").unwrap();
        username == username_test && password == password_test
    }

    fn authenticate(session: ssh_session) -> bool {
        #![allow(non_upper_case_globals)]
        loop {
            let message = unsafe { ssh_message_get(session) };
            if message.is_null() {
                return false;
            }
            let msg_type = unsafe { ssh_message_type(message) }.try_into();
            if msg_type == Ok(ssh_requests_e_SSH_REQUEST_AUTH) {
                let msg_subtype = unsafe { ssh_message_subtype(message) }.try_into();
                if msg_subtype == Ok(SSH_AUTH_METHOD_PASSWORD) {
                    println!("Got SSH_AUTH_METHOD_PASSWORD");
                    let user = unsafe { ssh_message_auth_user(message) };
                    let pwd = unsafe { ssh_message_auth_password(message) };
                    if !user.is_null() && !pwd.is_null() {
                        let user: &CStr = unsafe { CStr::from_ptr(user) };
                        let pwd: &CStr = unsafe { CStr::from_ptr(pwd) };
                        if check_username_password(user, pwd) {
                            unsafe {
                                ssh_message_auth_reply_success(message, 0);
                                ssh_message_free(message);
                            }
                            return true;
                        }
                    }
                }
            }
            unsafe {
                ssh_message_auth_set_methods(message, SSH_AUTH_METHOD_PASSWORD.try_into().unwrap());
                ssh_message_reply_default(message);
                ssh_message_free(message);
            }
        }
    }

    fn wait_for_channel(session: ssh_session) -> Option<ssh_channel> {
        #![allow(non_upper_case_globals)]
        loop {
            let message = unsafe { ssh_message_get(session) };
            if message.is_null() {
                return None;
            }
            println!("ssh_message_type");
            let msg_type = unsafe { ssh_message_type(message) }.try_into();
            println!("ssh_message_type {:?}", msg_type);

            if msg_type == Ok(ssh_requests_e_SSH_REQUEST_CHANNEL_OPEN) {
                println!("try parse msg_subtype");
                let msg_subtype = unsafe { ssh_message_subtype(message) }.try_into();
                println!("msg_subtype: {:?}", msg_subtype);
                if msg_subtype == Ok(ssh_channel_type_e_SSH_CHANNEL_DIRECT_TCPIP) {
                    let chan = unsafe { ssh_message_channel_request_open_reply_accept(message) };
                    unsafe {
                        ssh_message_free(message);
                    }
                    return Some(chan);
                }
            }
            println!("reply_default");
            unsafe {
                ssh_message_reply_default(message);
                ssh_message_free(message);
            }
        }
    }

    fn check_file_exists(file: &str) -> Result<&str> {
        File::open(file).map_err(|x| format!("{}: {}", x, file))?;
        Ok(file)
    }

    fn set_bind_option(ssh_bind: ssh_bind, key: ssh_bind_options_e, value: &str) {
        let c_str = CString::new(value).expect("CString::new failed");
        unsafe {
            ssh_bind_options_set(ssh_bind, key, c_str.as_ptr() as *const std::os::raw::c_void);
        };
    }
}
