#![forbid(unsafe_code)]

//! A disposable loopback-only L4 test fault injector.
//!
//! It only copies TCP bytes. In particular it has no TLS configuration and never
//! observes, parses, stores, or logs application/TLS payloads. A trigger drops
//! the first nonempty upstream-to-client response after the trigger.

use std::{net::SocketAddr, sync::Arc};

use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::{TcpListener, TcpStream},
    sync::Mutex,
};

#[derive(Default, Debug)]
struct Counters {
    triggers: u64,
    dropped_responses: u64,
}

#[derive(Default, Debug)]
struct LossGate {
    armed: bool,
    counters: Counters,
}

impl LossGate {
    fn trigger(&mut self) -> u64 {
        self.armed = true;
        self.counters.triggers += 1;
        self.counters.triggers
    }

    fn take_response_loss(&mut self, connection: &mut ConnectionState) -> bool {
        // A trigger belongs to the first *live* response receiver.  The same
        // mutex arbitration is used by the client reader and backend reader so
        // an EOF observed before the first backend byte cannot consume it.
        if !self.armed || !connection.client_read_half_active || connection.proxy_cut {
            return false;
        }
        self.armed = false;
        connection.proxy_cut = true;
        self.counters.dropped_responses += 1;
        true
    }
}

#[derive(Debug, Default)]
struct ConnectionState {
    // This is the client-to-proxy read half.  Once it has ended, the proxy no
    // longer manufactures a response loss for that connection.  In particular,
    // a client that has already closed cannot steal an armed trigger from a
    // later live connection.
    client_read_half_active: bool,
    proxy_cut: bool,
}

fn loopback(address: &str) -> Result<SocketAddr, &'static str> {
    let address: SocketAddr = address.parse().map_err(|_| "invalid address")?;
    address
        .ip()
        .is_loopback()
        .then_some(address)
        .ok_or("non-loopback address")
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    if let Err(error) = run().await {
        eprintln!("dtx-android-response-loss-proxy: {error}");
        return std::process::ExitCode::FAILURE;
    }
    std::process::ExitCode::SUCCESS
}

async fn run() -> Result<(), String> {
    let mut args = std::env::args().skip(1);
    let Some(listen) = args.next() else {
        return Err("expected listen, upstream, and control addresses".into());
    };
    let Some(upstream) = args.next() else {
        return Err("expected listen, upstream, and control addresses".into());
    };
    let Some(control_address) = args.next() else {
        return Err("expected listen, upstream, and control addresses".into());
    };
    if args.next().is_some() {
        return Err("invalid loopback-only configuration".into());
    }
    let (Ok(listen), Ok(upstream), Ok(control_address)) = (
        loopback(&listen),
        loopback(&upstream),
        loopback(&control_address),
    ) else {
        return Err("invalid loopback-only configuration".into());
    };
    let listener = TcpListener::bind(listen)
        .await
        .map_err(|_| "failed to bind proxy listener")?;
    let control_listener = TcpListener::bind(control_address)
        .await
        .map_err(|_| "failed to bind control listener")?;
    let gate = Arc::new(Mutex::new(LossGate::default()));
    let accept_proxy = async {
        loop {
            let (client, _) = listener.accept().await.map_err(|_| "proxy listener died")?;
            let gate = Arc::clone(&gate);
            tokio::spawn(async move {
                Box::pin(relay(client, upstream, gate)).await;
            });
        }
        #[allow(unreachable_code)]
        Ok::<(), String>(())
    };
    let control_gate = Arc::clone(&gate);
    let accept_control = async move {
        loop {
            let (socket, _) = control_listener
                .accept()
                .await
                .map_err(|_| "control listener died")?;
            let gate = Arc::clone(&control_gate);
            tokio::spawn(async move {
                control(socket, gate).await;
            });
        }
        #[allow(unreachable_code)]
        Ok::<(), String>(())
    };
    tokio::select! {
        result = accept_proxy => result,
        result = accept_control => result,
    }
}

async fn control(mut socket: TcpStream, gate: Arc<Mutex<LossGate>>) {
    let mut request = [0_u8; 256];
    let Ok(read) = socket.read(&mut request).await else {
        return;
    };
    let response = if request[..read].starts_with(b"POST /trigger ") {
        gate.lock().await.trigger();
        b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n".to_vec()
    } else if request[..read].starts_with(b"GET /counters ") {
        let gate = gate.lock().await;
        // Counters are the only observable state: neither request nor response bytes leave this process.
        let body = format!(
            "triggers={} dropped_responses={}\n",
            gate.counters.triggers, gate.counters.dropped_responses
        );
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
        .into_bytes()
    } else {
        b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_vec()
    };
    let _ = socket.write_all(&response).await;
}

async fn relay(client: TcpStream, upstream: SocketAddr, gate: Arc<Mutex<LossGate>>) {
    let Ok(server) = TcpStream::connect(upstream).await else {
        return;
    };
    let (mut client_read, mut client_write) = client.into_split();
    let (mut server_read, mut server_write) = server.into_split();
    let connection = Arc::new(Mutex::new(ConnectionState {
        client_read_half_active: true,
        proxy_cut: false,
    }));
    let reader_connection = Arc::clone(&connection);
    let forward = tokio::spawn(async move {
        let result = tokio::io::copy(&mut client_read, &mut server_write).await;
        reader_connection.lock().await.client_read_half_active = false;
        result
    });
    let mut buffer = [0_u8; 16_384];
    while let Ok(read) = server_read.read(&mut buffer).await {
        if read == 0 {
            break;
        }
        // Hold both state machines while deciding the first backend byte.  The
        // only other writer is the client read-half completion above.
        let should_cut = {
            let mut connection = connection.lock().await;
            gate.lock().await.take_response_loss(&mut connection)
        };
        if should_cut {
            break;
        }
        if client_write.write_all(&buffer[..read]).await.is_err() {
            break;
        }
    }
    forward.abort();
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use tokio::{
        io::{AsyncReadExt as _, AsyncWriteExt as _},
        net::{TcpListener, TcpStream},
        sync::Mutex,
        time::{Duration, sleep},
    };

    use super::{ConnectionState, LossGate, loopback, relay};

    #[test]
    fn loss_is_exactly_once_per_trigger_and_counters_are_deterministic() {
        let mut gate = LossGate::default();
        let mut connection = ConnectionState {
            client_read_half_active: true,
            proxy_cut: false,
        };
        assert!(!gate.take_response_loss(&mut connection));
        assert_eq!(gate.trigger(), 1);
        assert!(gate.take_response_loss(&mut connection));
        assert!(!gate.take_response_loss(&mut connection));
        assert_eq!(gate.trigger(), 2);
        assert_eq!(gate.trigger(), 3);
        connection.proxy_cut = false;
        assert!(gate.take_response_loss(&mut connection));
        assert_eq!(gate.counters.triggers, 3);
        assert_eq!(gate.counters.dropped_responses, 2);
    }

    #[test]
    fn listeners_and_upstreams_must_be_literal_loopback() {
        assert!(loopback("127.0.0.1:1").is_ok());
        assert!(loopback("[::1]:1").is_ok());
        assert!(loopback("0.0.0.0:1").is_err());
        assert!(loopback("192.168.1.10:1").is_err());
    }

    #[tokio::test]
    async fn actual_tcp_response_is_cut_once_after_trigger() {
        let backend = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let backend_address = backend.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut socket, _) = backend.accept().await.unwrap();
            let mut request = [0; 1];
            socket.read_exact(&mut request).await.unwrap();
            socket.write_all(b"response").await.unwrap();
        });
        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_address = proxy.local_addr().unwrap();
        let gate = Arc::new(Mutex::new(LossGate::default()));
        gate.lock().await.trigger();
        let relay_gate = Arc::clone(&gate);
        tokio::spawn(async move {
            let (client, _) = proxy.accept().await.unwrap();
            Box::pin(relay(client, backend_address, relay_gate)).await;
        });
        let mut client = TcpStream::connect(proxy_address).await.unwrap();
        client.write_all(b"x").await.unwrap();
        let mut response = [0; 8];
        assert_eq!(client.read(&mut response).await.unwrap(), 0);
        assert_eq!(gate.lock().await.counters.dropped_responses, 1);
    }

    #[tokio::test]
    async fn closed_client_does_not_consume_trigger() {
        let mut gate = LossGate::default();
        gate.trigger();
        let mut connection = ConnectionState {
            client_read_half_active: false,
            proxy_cut: false,
        };
        assert!(!gate.take_response_loss(&mut connection));
        assert_eq!(gate.counters.dropped_responses, 0);
    }

    #[tokio::test]
    async fn tcp_half_close_is_arbitrated_before_the_first_backend_byte() {
        let backend = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let backend_address = backend.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut socket, _) = backend.accept().await.unwrap();
            let mut request = [0; 1];
            socket.read_exact(&mut request).await.unwrap();
            // The client-to-proxy half closes before this response exists.
            socket.write_all(b"response").await.unwrap();
        });
        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_address = proxy.local_addr().unwrap();
        let gate = Arc::new(Mutex::new(LossGate::default()));
        gate.lock().await.trigger();
        let relay_gate = Arc::clone(&gate);
        tokio::spawn(async move {
            let (client, _) = proxy.accept().await.unwrap();
            Box::pin(relay(client, backend_address, relay_gate)).await;
        });
        let mut client = TcpStream::connect(proxy_address).await.unwrap();
        client.write_all(b"x").await.unwrap();
        client.shutdown().await.unwrap();
        let mut response = [0; 8];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"response");
        let gate = gate.lock().await;
        assert_eq!(gate.counters.dropped_responses, 0);
        assert!(gate.armed);
    }

    #[tokio::test]
    async fn fully_closed_tcp_client_cannot_consume_a_later_response_trigger() {
        let backend = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let backend_address = backend.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut socket, _) = backend.accept().await.unwrap();
            let mut request = [0; 1];
            socket.read_exact(&mut request).await.unwrap();
            // Let the relay observe the complete client close before a byte is
            // available to arbitrate against the shared one-shot gate.
            sleep(Duration::from_millis(25)).await;
            socket.write_all(b"response").await.unwrap();
        });
        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_address = proxy.local_addr().unwrap();
        let gate = Arc::new(Mutex::new(LossGate::default()));
        gate.lock().await.trigger();
        let relay_gate = Arc::clone(&gate);
        tokio::spawn(async move {
            let (client, _) = proxy.accept().await.unwrap();
            relay(client, backend_address, relay_gate).await;
        });
        let mut client = TcpStream::connect(proxy_address).await.unwrap();
        client.write_all(b"x").await.unwrap();
        drop(client);
        sleep(Duration::from_millis(50)).await;
        let gate = gate.lock().await;
        assert_eq!(gate.counters.dropped_responses, 0);
        assert!(gate.armed);
    }

    #[tokio::test]
    async fn concurrent_tcp_connections_consume_each_trigger_exactly_once() {
        let backend = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let backend_address = backend.local_addr().unwrap();
        tokio::spawn(async move {
            for _ in 0..2 {
                let (mut socket, _) = backend.accept().await.unwrap();
                tokio::spawn(async move {
                    let mut request = [0; 1];
                    socket.read_exact(&mut request).await.unwrap();
                    socket.write_all(b"response").await.unwrap();
                });
            }
        });
        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_address = proxy.local_addr().unwrap();
        let gate = Arc::new(Mutex::new(LossGate::default()));
        gate.lock().await.trigger();
        let relay_gate = Arc::clone(&gate);
        tokio::spawn(async move {
            for _ in 0..2 {
                let (client, _) = proxy.accept().await.unwrap();
                let relay_gate = Arc::clone(&relay_gate);
                tokio::spawn(async move { relay(client, backend_address, relay_gate).await });
            }
        });
        let mut first = TcpStream::connect(proxy_address).await.unwrap();
        let mut second = TcpStream::connect(proxy_address).await.unwrap();
        first.write_all(b"x").await.unwrap();
        second.write_all(b"y").await.unwrap();
        let mut first_response = Vec::new();
        let mut second_response = Vec::new();
        first.read_to_end(&mut first_response).await.unwrap();
        second.read_to_end(&mut second_response).await.unwrap();
        assert_eq!(
            usize::from(first_response == b"response")
                + usize::from(second_response == b"response"),
            1
        );
        assert_eq!(
            usize::from(first_response.is_empty()) + usize::from(second_response.is_empty()),
            1
        );
        let gate = gate.lock().await;
        assert_eq!(gate.counters.triggers, 1);
        assert_eq!(gate.counters.dropped_responses, 1);
    }
}
