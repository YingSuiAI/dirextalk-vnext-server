#![forbid(unsafe_code)]

//! A disposable loopback-only L4 test fault injector.
//!
//! It only copies TCP bytes. In particular it has no TLS configuration and never
//! observes, parses, stores, or logs application/TLS payloads. A trigger drops
//! the first nonempty upstream-to-client response after the trigger.

use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

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

    fn take_response_loss(&mut self, client_open: bool) -> bool {
        if !self.armed || !client_open {
            return false;
        }
        self.armed = false;
        self.counters.dropped_responses += 1;
        true
    }
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
async fn main() {
    let mut args = std::env::args().skip(1);
    let Some(listen) = args.next() else {
        fail();
        return;
    };
    let Some(upstream) = args.next() else {
        fail();
        return;
    };
    let Some(control_address) = args.next() else {
        fail();
        return;
    };
    if args.next().is_some() {
        fail();
        return;
    }
    let (Ok(listen), Ok(upstream), Ok(control_address)) = (
        loopback(&listen),
        loopback(&upstream),
        loopback(&control_address),
    ) else {
        fail();
        return;
    };
    let Ok(listener) = TcpListener::bind(listen).await else {
        fail();
        return;
    };
    let Ok(control_listener) = TcpListener::bind(control_address).await else {
        fail();
        return;
    };
    let gate = Arc::new(Mutex::new(LossGate::default()));
    let control_gate = Arc::clone(&gate);
    tokio::spawn(async move {
        while let Ok((socket, _)) = control_listener.accept().await {
            let gate = Arc::clone(&control_gate);
            tokio::spawn(async move {
                control(socket, gate).await;
            });
        }
    });
    while let Ok((client, _)) = listener.accept().await {
        let gate = Arc::clone(&gate);
        tokio::spawn(async move {
            Box::pin(relay(client, upstream, gate)).await;
        });
    }
}

fn fail() {
    eprintln!("dtx-android-response-loss-proxy: invalid loopback-only configuration");
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
    let client_open = Arc::new(AtomicBool::new(true));
    let reader_open = Arc::clone(&client_open);
    let forward = tokio::spawn(async move {
        let result = tokio::io::copy(&mut client_read, &mut server_write).await;
        reader_open.store(false, Ordering::Release);
        result
    });
    let mut buffer = [0_u8; 16_384];
    while let Ok(read) = server_read.read(&mut buffer).await {
        if read == 0 {
            break;
        }
        // The mutex makes trigger/response consumption one-shot. A closed client
        // cannot consume a trigger or increment the drop counter.
        if gate
            .lock()
            .await
            .take_response_loss(client_open.load(Ordering::Acquire))
        {
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
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };

    use tokio::{
        io::{AsyncReadExt as _, AsyncWriteExt as _},
        net::{TcpListener, TcpStream},
        sync::Mutex,
    };

    use super::{LossGate, loopback, relay};

    #[test]
    fn loss_is_exactly_once_per_trigger_and_counters_are_deterministic() {
        let mut gate = LossGate::default();
        assert!(!gate.take_response_loss(true));
        assert_eq!(gate.trigger(), 1);
        assert!(gate.take_response_loss(true));
        assert!(!gate.take_response_loss(true));
        assert_eq!(gate.trigger(), 2);
        assert_eq!(gate.trigger(), 3);
        assert!(gate.take_response_loss(true));
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
        let client_open = AtomicBool::new(false);
        assert!(!gate.take_response_loss(client_open.load(Ordering::Acquire)));
        assert_eq!(gate.counters.dropped_responses, 0);
    }
}
