use std::{
    borrow::Cow,
    error::Error,
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    thread::JoinHandle,
};

use futures::FutureExt;
use ssh_jumper::{
    model::{HostAddress, HostSocketParams, JumpHostAuthParams, SshTunnelParams},
    SshJumper,
};
use tokio::{
    net::{TcpListener, TcpStream},
    runtime,
    sync::{mpsc, oneshot},
};

const LOCALHOST_ADDR: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

#[test]
fn ssh_jumper_connect() -> Result<(), Box<dyn Error>> {
    let rt = runtime::Builder::new_multi_thread().enable_io().build()?;
    let local_port = 0;
    let jump_host_ssh_port = 2222;
    let target_port = 8080;

    rt.block_on::<_>(async move {
        let target_bytes_received =
            tokio::task::spawn(
                async move { target_host_listen(target_port).await.unwrap_or([1; 32]) },
            );

        // Forward port 1234 to 8080 through SSH server at 2222
        //
        // ssh -i ~/.ssh/id_rsa -L 1234:127.0.0.1:8080 my_user@127.0.0.1:2222
        let (client_done_tx, server_thread_handler) = ssh_server_spawn(jump_host_ssh_port).await?;

        match ssh_connection_open(local_port, jump_host_ssh_port, target_port).await {
            Ok((local_socket_addr, ssh_error_rx)) => {
                println!("SSH Jumper connected: {}", local_socket_addr);

                local_bytes_send(local_socket_addr, b"test: ssh_jumper_connect").await?;

                futures::select! {
                    ssh_error = ssh_error_rx.fuse() => {
                        if let Err(e) = ssh_error {
                            println!("Received SSH error: {}", e);
                        }
                    }
                    target_bytes_received = target_bytes_received.fuse() => {
                        let target_bytes_received = target_bytes_received?;
                        assert_eq!(b"test: ssh_jumper_connect", &target_bytes_received[0..24]);
                    }
                }

                // let target_bytes_received = target_bytes_received.await?;
                // assert_eq!(b"test: ssh_jumper_connect", &target_bytes_received[0..24]);

                client_done_notify(client_done_tx).await;
                server_done_join(server_thread_handler);
            }
            Err(e) => {
                server_done_join(server_thread_handler);
                panic!("Failed to open SSH connection: {}", e);
            }
        }

        Result::<_, Box<dyn Error>>::Ok(())
    })?;

    Ok(())
}

// https://docs.rs/tokio/latest/tokio/net/struct.TcpStream.html#method.try_read
async fn target_host_listen(target_port: u16) -> Result<[u8; 32], Box<dyn Error>> {
    let target_socket_addr: SocketAddr = (LOCALHOST_ADDR, target_port).into();
    let listener = TcpListener::bind(target_socket_addr).await?;
    println!(
        "target about to accept connections at: {}.",
        target_socket_addr
    );
    let (stream, _) = listener.accept().await?;
    println!("target accepted a connection.");

    // Send some data from target host to local.
    println!("target waiting for stream to be writable.");
    stream.writable().await?;
    match stream.try_write(b"rararara") {
        Ok(n) => {
            println!("target wrote {} bytes.", n);
        }
        Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
            println!("target write would block.");
        }
        Err(e) => {
            println!("target write error: {}", e);
        }
    }

    // Read data sent from local through tunnel.
    loop {
        println!("target waiting for stream to be readable.");
        // Wait for the socket to be readable
        stream.readable().await?;

        // Creating the buffer **after** the `await` prevents it from
        // being stored in the async task.
        let mut buf = [0; 32];

        // Try to read data, this may still fail with `WouldBlock`
        // if the readiness event is a false positive.
        println!("target trying to read stream.");
        match stream.try_read(&mut buf) {
            Ok(0) => {
                println!("target read 0 bytes.");
                return Ok(buf);
            }
            Ok(n) => {
                println!("target read {} bytes", n);
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                println!("target read would block.");
                continue;
            }
            Err(e) => {
                println!("target read errored: {}", e);
                return Err(e.into());
            }
        }
    }
}

// https://docs.rs/tokio/latest/tokio/net/struct.TcpStream.html#method.try_write
async fn local_bytes_send(
    local_socket_addr: SocketAddr,
    bytes: &[u8],
) -> Result<(), Box<dyn Error>> {
    println!("local about to connect to {}.", local_socket_addr);
    let stream = TcpStream::connect(local_socket_addr).await?;
    println!("local connected.");

    loop {
        // Wait for the socket to be writable
        stream.writable().await?;

        // Try to write data, this may still fail with `WouldBlock`
        // if the readiness event is a false positive.
        match stream.try_write(bytes) {
            Ok(n) => {
                println!("local wrote {} bytes.", n);
                return Ok(());
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                continue;
            }
            Err(e) => {
                return Err(e.into());
            }
        }
    }
}

fn server_done_join(server_thread_handler: JoinHandle<()>) {
    server_thread_handler
        .join()
        .expect("Failed to wait for SSH server thread to finish.");
}

async fn client_done_notify(client_done_tx: mpsc::Sender<ClientDone>) {
    println!("Client Done");
    client_done_tx
        .send(ClientDone)
        .await
        .expect("Failed to notify server that client is done.");
}

async fn ssh_server_spawn(
    jump_host_ssh_port: u16,
) -> Result<(mpsc::Sender<ClientDone>, std::thread::JoinHandle<()>), Box<dyn Error>> {
    let (server_ready_tx, server_ready_rx) = oneshot::channel::<ServerReady>();
    let (client_done_tx, client_done_rx) = mpsc::channel::<ClientDone>(1);
    let server_thread_handler = std::thread::spawn(move || {
        let _ = ssh_server::open_server_socket(jump_host_ssh_port, server_ready_tx, client_done_rx);
    });
    server_ready_rx.await?;

    Ok((client_done_tx, server_thread_handler))
}

async fn ssh_connection_open(
    local_port: u16,
    jump_host_ssh_port: u16,
    target_port: u16,
) -> Result<(SocketAddr, oneshot::Receiver<io::Error>), ssh_jumper::model::Error> {
    let localhost_addr = HostAddress::IpAddr(LOCALHOST_ADDR);

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
    use core::ffi::c_void;
    use std::{
        convert::TryInto,
        error::Error,
        ffi::{CStr, CString},
        fs::File,
        io::{self, Read, Write},
        net::{IpAddr, SocketAddr, TcpStream},
        os::{
            raw::c_int,
            unix::prelude::{AsRawFd, FromRawFd, RawFd},
        },
        ptr,
        str::FromStr,
    };

    use libssh_sys_dylib::*;
    use tokio::sync::{mpsc::Receiver, oneshot::Sender};

    use crate::{ClientDone, ServerReady};

    type Result<T> = std::result::Result<T, Box<dyn Error + Send + Sync>>;

    pub fn open_server_socket(
        jump_host_ssh_port: u16,
        server_ready_tx: Sender<ServerReady>,
        mut client_done_rx: Receiver<ClientDone>,
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

        let server_ready_send_result = server_ready_tx.send(ServerReady);
        if server_ready_send_result.is_ok() {
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
            let channel_and_socket = wait_for_channel(session);
            match channel_and_socket {
                Some((channel, target_tcp_stream)) => {
                    println!("SSH server: Channel established");

                    // Forward traffic.
                    let mainloop_event = unsafe { ssh_event_new() };
                    forward_direct_tcp_ip_data(channel, &target_tcp_stream, mainloop_event);
                    println!("SSH server: Callbacks set.");

                    let mut poll_count = 3;
                    loop {
                        println!("SSH server: polling");
                        let poll_result = unsafe { ssh_event_dopoll(mainloop_event, 100) };
                        if poll_result == SSH_ERROR {
                            println!("SSH server: poll error");
                            break;
                        }

                        poll_count -= 1;
                        if poll_count == 0 {
                            break;
                        }
                    }

                    println!("SSH server: waiting for client to be done.");
                    client_done_rx.blocking_recv();
                }
                None => {
                    println!("Channel not opened");
                }
            }
        } else {
            println!("failed to send server_ready");
        }

        unsafe {
            ssh_disconnect(session);
            ssh_free(session);
            ssh_bind_free(ssh_bind);
            ssh_finalize();
        }

        Ok(())
    }

    // https://git.libssh.org/projects/libssh.git/tree/examples/sshd_direct-tcpip.c
    fn forward_direct_tcp_ip_data(
        ssh_channel: *mut ssh_channel_struct,
        target_tcp_steam: &TcpStream,
        mainloop_event: ssh_event,
    ) {
        let target_tcp_stream_fd = target_tcp_steam.as_raw_fd();
        let event_fd_data = Box::new(EventFdDataStruct {
            ssh_channel,
            target_tcp_stream_fd,
        });
        let event_fd_data_ptr = Box::<_>::into_raw(event_fd_data) as *mut c_void;
        let mut ssh_channel_callbacks = ssh_channel_callbacks_struct {
            size: 0,                                         // usize,
            userdata: event_fd_data_ptr,                     // *mut c_void,
            channel_data_function: Some(my_channel_data_fn), // ssh_channel_data_callback,
            channel_eof_function: None,                      // ssh_channel_eof_callback,
            channel_close_function: None,                    // ssh_channel_close_callback,
            channel_signal_function: None,                   // ssh_channel_signal_callback,
            channel_exit_status_function: None,              // ssh_channel_exit_status_callback,
            channel_exit_signal_function: None,              // ssh_channel_exit_signal_callback,
            channel_pty_request_function: None,              // ssh_channel_pty_request_callback,
            channel_shell_request_function: None,            // ssh_channel_shell_request_callback,
            channel_auth_agent_req_function: None,           // ssh_channel_auth_agent_req_callback,
            channel_x11_req_function: None,                  // ssh_channel_x11_req_callback,
            channel_pty_window_change_function: None, // ssh_channel_pty_window_change_callback,
            channel_exec_request_function: None,      // ssh_channel_exec_request_callback,
            channel_env_request_function: None,       // ssh_channel_env_request_callback,
            channel_subsystem_request_function: None, // ssh_channel_subsystem_request_callback,
            channel_write_wontblock_function: None,   // ssh_channel_write_wontblock_callback,
        };

        // Hopefully does the same function as `ssh_callbacks_init`
        // See <https://github.com/substack/libssh/blob/c073979/include/libssh/callbacks.h#L189-L191>
        ssh_channel_callbacks.size = std::mem::size_of::<ssh_channel_callbacks_struct>();
        println!(
            "SSH Server: ssh_channel_callbacks.size: {}",
            ssh_channel_callbacks.size
        );
        unsafe { ssh_set_channel_callbacks(ssh_channel, ptr::addr_of_mut!(ssh_channel_callbacks)) };
        unsafe {
            ssh_event_add_fd(
                mainloop_event,
                target_tcp_stream_fd,
                libc::POLLIN,
                Some(my_fd_data_function),
                event_fd_data_ptr,
            )
        };
    }

    // Streams bytes from channel to target tcp stream when libssh invokes callback.
    extern "C" fn my_channel_data_fn(
        _session: ssh_session,
        _channel: ssh_channel,
        data: *mut c_void,
        len: u32,
        _is_stderr: c_int,
        userdata: *mut c_void,
    ) -> c_int {
        println!("!!! my_channel_data_fn called !!!");
        let len: usize = len.try_into().unwrap();
        let event_fd_data =
            unsafe { Box::<EventFdDataStruct>::from_raw(userdata as *mut EventFdDataStruct) };
        let mut target_tcp_stream =
            unsafe { TcpStream::from_raw_fd(event_fd_data.target_tcp_stream_fd) };

        let mut bytes = Vec::<u8>::with_capacity(len);
        unsafe { ptr::copy_nonoverlapping(data as *mut u8, bytes.as_mut_ptr(), len) };

        let n_bytes_written;

        loop {
            // Try to write data, this may still fail with `WouldBlock`
            // if the readiness event is a false positive.
            match target_tcp_stream.write(&bytes) {
                Ok(n) => {
                    println!("SSH server forward target to local: {} bytes.", n);
                    n_bytes_written = n.try_into().unwrap();
                    break;
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    continue;
                }
                Err(e) => {
                    println!("Error while forwarding data: {}", e);
                    n_bytes_written = -1;
                    break;
                }
            }
        }

        // Don't kill the TCP stream, the server still owns it.
        std::mem::forget(target_tcp_stream);

        Box::leak(event_fd_data);

        n_bytes_written
    }

    // Streams bytes from target tcp stream to channel when libssh invokes callback.
    unsafe extern "C" fn my_fd_data_function(
        _fd: socket_t,
        _revents: c_int,
        userdata: *mut c_void,
    ) -> c_int {
        let mut n_bytes_read = 0;
        let event_fd_data = Box::<EventFdDataStruct>::from_raw(userdata as *mut EventFdDataStruct);
        println!(
            "my_fd_data_function called: tcp_stream_fd: {}",
            event_fd_data.target_tcp_stream_fd
        );
        let channel = event_fd_data.ssh_channel;
        let mut target_tcp_stream = TcpStream::from_raw_fd(event_fd_data.target_tcp_stream_fd);

        let session = ssh_channel_get_session(channel);

        let session_blocking_previous = ssh_is_blocking(session);
        ssh_set_blocking(session, 0);

        // Read from target tcp stream and write it to channel.
        'outer: loop {
            // Creating the buffer **after** the `await` prevents it from
            // being stored in the async task.
            let mut buf = [0; 32];

            // Try to read data, this may still fail with `WouldBlock`
            // if the readiness event is a false positive.
            match target_tcp_stream.read(&mut buf) {
                Ok(0) => {
                    ssh_channel_send_eof(channel);
                }
                Ok(n) => {
                    if ssh_channel_is_open(channel) == 1 {
                        println!("SSH server read {} bytes from target", n);
                        n_bytes_read = n;
                        let n_i32: i32 = n.try_into().unwrap();
                        let n_u32: u32 = n.try_into().unwrap();

                        // Write from target to client channel
                        let mut bytes_written_total = 0;
                        loop {
                            let bytes_written_now = ssh_channel_write(
                                channel,
                                ptr::addr_of!(buf) as *const c_void,
                                n_u32,
                            );
                            if bytes_written_now < 0 {
                                println!(
                                    "SSH server: Error writing on the direct-tcpip channel: {}",
                                    bytes_written_now
                                );
                                break;
                            }
                            bytes_written_total += bytes_written_now;
                            println!(
                                "SSH server write bytes from target to channel ({} from {})",
                                bytes_written_total, n_i32
                            );

                            if bytes_written_now == 0 || bytes_written_total == n_i32 {
                                break 'outer;
                            }
                        }
                    } else {
                        println!("SSH server: Can't write on closed channel!");
                        break;
                    }
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    break;
                }
                Err(e) => {
                    println!("Error while reading from target tcp stream: {}", e);
                    break;
                }
            }
        }

        // Don't kill the TCP stream, the server still owns it.
        std::mem::forget(target_tcp_stream);

        Box::leak(event_fd_data);

        ssh_set_blocking(session, session_blocking_previous);

        println!("SSH server leaving my_fd_data_function");

        n_bytes_read.try_into().unwrap()
    }

    fn server_to_target_connect(message: ssh_message) -> Result<TcpStream> {
        let target_hostname =
            unsafe { CStr::from_ptr(ssh_message_channel_request_open_destination(message)) }
                .to_owned()
                .into_string()
                .unwrap();
        let target_port: u16 = unsafe {
            ssh_message_channel_request_open_destination_port(message)
                .try_into()
                .unwrap()
        };

        let target_socket_addr: SocketAddr = (
            IpAddr::from_str(target_hostname.as_str()).unwrap(),
            target_port,
        )
            .into();

        println!("SSH server about to connect to {}.", target_socket_addr);
        let stream = TcpStream::connect(target_socket_addr)?;
        println!("SSH server connected to {}.", target_socket_addr);

        Ok(stream)
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

    fn wait_for_channel(session: ssh_session) -> Option<(ssh_channel, TcpStream)> {
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
                    let channel = unsafe { ssh_message_channel_request_open_reply_accept(message) };
                    let target_tcp_stream = server_to_target_connect(message).unwrap();

                    unsafe {
                        ssh_message_free(message);
                    }
                    return Some((channel, target_tcp_stream));
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

    struct EventFdDataStruct {
        ssh_channel: *mut ssh_channel_struct,
        target_tcp_stream_fd: RawFd,
    }
}

#[derive(Debug)]
pub struct ServerReady;

#[derive(Debug)]
pub struct ClientDone;

#[derive(Debug)]
pub struct TestDone;
