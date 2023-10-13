#![no_main]
#![no_std]

extern crate alloc;

use alloc::{borrow::Cow, format, string::String};
use ministd::{
    dbg, entry, io,
    net::{TcpStream, ToSocketAddrs},
};
use rustls::{ClientConfig, RootCertStore};

const SERVER_NAME: &str = "www.rust-lang.org";
const PORT: u16 = 443;

entry!(main);

fn main() -> io::Result<()> {
    let mut root_store = RootCertStore::empty();
    root_store.extend(
        webpki_roots::TLS_SERVER_ROOTS
            .iter()
            .cloned(),
    );

    let mut config = ClientConfig::builder_with_provider(demo::CRYPTO_PROVIDER)
        .with_safe_defaults()
        .dangerous()
        .with_custom_certificate_verifier(demo::certificate_verifier(root_store))
        .with_no_client_auth();

    config.time_provider = demo::time_provider();

    let sock_addr = (SERVER_NAME, PORT)
        .to_socket_addrs()?
        .next()
        .ok_or(io::Error::AddressLookup)?;
    dbg!(sock_addr);

    let _sock = TcpStream::connect(&sock_addr)?;
    let _request = http_request(SERVER_NAME);

    // TODO

    Ok(())
}

fn http_request(server_name: &str) -> String {
    const HTTP_SEPARATOR: &str = "\r\n";

    let lines = [
        Cow::Borrowed("GET / HTTP/1.1"),
        format!("Host: {server_name}").into(),
        "Connection: close".into(),
        "Accept-Encoding: identity".into(),
        "".into(), // body
    ];

    let mut req = String::new();
    for line in lines {
        req.push_str(&line);
        req.push_str(HTTP_SEPARATOR);
    }

    req
}
