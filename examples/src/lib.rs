use std::error::Error;
use std::fs::File;
use std::io::{BufReader, Read, Write};
use std::net::TcpStream;

use rustls::client::ClientConnectionData;
use rustls::unbuffered::{InsufficientSizeError, MayEncryptAppData};
use rustls::RootCertStore;

pub fn build_root_store(certfile: Option<&str>) -> Result<RootCertStore, Box<dyn Error>> {
    let mut root_store = RootCertStore::empty();
    if let Some(path) = certfile {
        let certfile = File::open(path)?;
        let mut reader = BufReader::new(certfile);
        root_store.add_parsable_certificates(
            rustls_pemfile::certs(&mut reader).collect::<Result<Vec<_>, _>>()?,
        );
    } else {
        root_store.extend(
            webpki_roots::TLS_SERVER_ROOTS
                .iter()
                .cloned(),
        );
    }
    Ok(root_store)
}

pub fn encrypt_http_request(
    sent_request: &mut bool,
    may_encrypt: &mut MayEncryptAppData<'_, ClientConnectionData>,
    outgoing_tls: &mut [u8],
    outgoing_used: &mut usize,
    http_request: &[u8],
) -> bool {
    if !*sent_request {
        let written = may_encrypt
            .encrypt(http_request, &mut outgoing_tls[*outgoing_used..])
            .expect("encrypted request does not fit in `outgoing_tls`");
        *outgoing_used += written;
        *sent_request = true;
        eprintln!("queued HTTP request");
        true
    } else {
        false
    }
}

pub fn try_or_resize_and_retry<E>(
    mut f: impl FnMut(&mut [u8]) -> Result<usize, E>,
    map_err: impl FnOnce(E) -> Result<InsufficientSizeError, Box<dyn Error>>,
    outgoing_tls: &mut Vec<u8>,
    outgoing_used: &mut usize,
) -> Result<usize, Box<dyn Error>>
where
    E: Error + 'static,
{
    let written = match f(&mut outgoing_tls[*outgoing_used..]) {
        Ok(written) => written,

        Err(e) => {
            let InsufficientSizeError { required_size } = map_err(e)?;
            let new_len = *outgoing_used + required_size;
            outgoing_tls.resize(new_len, 0);
            eprintln!("resized `outgoing_tls` buffer to {new_len}B");

            f(&mut outgoing_tls[*outgoing_used..])?
        }
    };

    *outgoing_used += written;

    Ok(written)
}

pub fn recv_tls(
    sock: &mut TcpStream,
    incoming_tls: &mut [u8],
    incoming_used: &mut usize,
) -> Result<(), Box<dyn Error>> {
    let read = sock.read(&mut incoming_tls[*incoming_used..])?;
    eprintln!("received {read}B of data");
    *incoming_used += read;
    Ok(())
}

pub fn send_tls(
    sock: &mut TcpStream,
    outgoing_tls: &[u8],
    outgoing_used: &mut usize,
) -> Result<(), Box<dyn Error>> {
    sock.write_all(&outgoing_tls[..*outgoing_used])?;
    eprintln!("sent {outgoing_used}B of data");
    *outgoing_used = 0;
    Ok(())
}

pub fn build_http_request(server_name: &str) -> Vec<u8> {
    format!("GET / HTTP/1.1\r\nHost: {server_name}\r\nConnection: close\r\nAccept-Encoding: identity\r\n\r\n").into_bytes()
}

pub const KB: usize = 1024;
