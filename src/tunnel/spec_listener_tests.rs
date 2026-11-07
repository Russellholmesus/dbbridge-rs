use std::io::Read;
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::client::TunnelListener;
use crate::net::Conn;

fn pair() -> (TcpStream, TcpStream) {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let a = TcpStream::connect(l.local_addr().unwrap()).unwrap();
    let (b, _) = l.accept().unwrap();
    (a, b)
}

#[test]
fn spec_listener_deliver_accept() {
    let l = Arc::new(TunnelListener::new());
    let (a, b) = pair();
    let expect = a.peer_addr().unwrap().to_string();
    let deliverer = {
        let l = l.clone();
        std::thread::spawn(move || l.deliver(Box::new(a)))
    };
    let got = l.accept_next().expect("accept");
    assert!(deliverer.join().unwrap(), "deliver failed");
    assert_eq!(got.describe(), expect, "accepted a different stream");
    drop(b);
}

#[test]
fn spec_listener_close_unblocks() {
    let l = Arc::new(TunnelListener::new());
    let (tx, rx) = std::sync::mpsc::channel();
    {
        let l = l.clone();
        std::thread::spawn(move || {
            let _ = tx.send(l.accept_next().is_none());
        });
    }
    std::thread::sleep(Duration::from_millis(10));
    l.close();
    assert!(
        rx.recv_timeout(Duration::from_secs(1))
            .expect("Accept blocked after Close"),
        "Accept returned a stream after Close"
    );
    let (a, _b) = pair();
    assert!(!l.deliver(Box::new(a)), "Deliver accepted after Close");
    l.close();
    assert!(l.is_closed(), "Done not closed");
}

#[test]
fn spec_listener_no_stranded_conns() {
    for round in 0..50 {
        let l = Arc::new(TunnelListener::new());
        let delivered = Arc::new(AtomicUsize::new(0));
        let accepted = Arc::new(AtomicUsize::new(0));
        let peers: Arc<Mutex<Vec<TcpStream>>> = Arc::default();
        let mut senders = Vec::new();
        for _ in 0..8 {
            let (l, delivered, peers) = (l.clone(), delivered.clone(), peers.clone());
            senders.push(std::thread::spawn(move || {
                let (a, b) = pair();
                if l.deliver(Box::new(a)) {
                    delivered.fetch_add(1, Ordering::SeqCst);
                    peers.lock().unwrap().push(b);
                }
            }));
        }
        let acceptor = {
            let (l, accepted) = (l.clone(), accepted.clone());
            std::thread::spawn(move || {
                while let Some(c) = l.accept_next() {
                    let _ = c.shutdown_both();
                    accepted.fetch_add(1, Ordering::SeqCst);
                }
            })
        };
        std::thread::sleep(Duration::from_millis(1));
        l.close();
        for s in senders {
            s.join().unwrap();
        }
        acceptor.join().unwrap();
        // Every delivered stream ended for its sender: accepted (and closed
        // by the acceptor) or shut down by Close.
        for mut b in peers.lock().unwrap().drain(..) {
            b.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
            let mut buf = [0u8; 1];
            assert!(
                matches!(b.read(&mut buf), Ok(0) | Err(_)),
                "round {round}: delivered stream stranded"
            );
            let _ = b.read(&mut buf);
        }
        assert!(
            accepted.load(Ordering::SeqCst) <= delivered.load(Ordering::SeqCst),
            "round {round}: accepted more than delivered"
        );
    }
}
