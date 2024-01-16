mod config;

use openssl::ssl::{SslConnector, SslMethod};
use rustls::{ClientConfig, RootCertStore, SupportedCipherSuite};
use std::{net::TcpStream, sync::Arc};
use x509_parser::prelude::*;

use std::io::{stdout, Read, Write};


use clap::Parser;

pub fn run() {
    //get_args();
    new_cert_data();
}

fn get_args() {
    let config = config::config::Config::parse();
    get_certificate_data_for_domain(&config.domain);
    new_cert_data();
}

fn new_cert_data() {
    let mut root_store = RootCertStore::empty();
    root_store.extend(
        webpki_roots::TLS_SERVER_ROOTS
            .iter()
            .cloned(),
    );

    // Allow using SSLKEYLOGFILE.
    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    // Allow using SSLKEYLOGFILE.
    config.key_log = Arc::new(rustls::KeyLogFile::new());

    let server_name = "www.google.com".try_into().unwrap();
    let mut conn = rustls::ClientConnection::new(Arc::new(config), server_name).unwrap();
    let mut sock = TcpStream::connect("www.google.com:443").unwrap();
    let mut tls = rustls::Stream::new(&mut conn, &mut sock);
   
    let tls_write_result = tls.write_all(
        concat!(
            "GET / HTTP/1.1\r\n",
            "Host: www.google.com\r\n",
            "Connection: close\r\n",
            "Accept-Encoding: identity\r\n",
            "\r\n"
        )
        .as_bytes(),
    );

    match tls_write_result {
        Ok(_val) => println!("Success"),
        Err(e) => println!("Error: {:?}", e),
    }

    let ciphersuite = tls
        .conn
        .negotiated_cipher_suite();
        

    match ciphersuite {
        Some(cipher) => {
            writeln!(
                &mut std::io::stderr(),
                "Current ciphersuite: {:?}",
                cipher.suite()
            )
            .unwrap();
            
        },
        None => {
            println!("Unable to determine suite");
        }
    };
    


    let server_cert_chain = conn.peer_certificates().unwrap();
    // Print information about each certificate in the chain
    for (index, cert) in server_cert_chain.iter().enumerate() {
        //let cert_pem = rustls::HandshakeType::Certificate
        //println!("{:?}", cert);
        let res = X509Certificate::from_der(cert.as_ref());
        match res {
            Ok((rem, cert)) => {
                assert!(rem.is_empty());
                //
                assert_eq!(cert.version(), X509Version::V3);
                println!("{:?}", get_issuer_common_name(&cert));
                println!("Valid From: {:?} -- Valid To: {:?}", cert.validity().not_before.to_datetime().date(),cert.validity().not_after.to_datetime().date());
                
                
            },
            _ => panic!("x509 parsing failed: {:?}", res),
        }
        println!();
    }
}

fn get_issuer_common_name<'a>(cert: &'a X509Certificate<'a>) -> &'a str {
    let mut issuer_name: &str = "";
    for (i, val) in cert.issuer().iter_common_name().enumerate() {
        //println!("{:?}", val.attr_value().data);
        issuer_name = match std::str::from_utf8(&val.attr_value().data) {
            Ok(v) => v,
            Err(e) => panic!("Invalid UTF-8 sequence: {}", e),
        };
    }
    issuer_name
}


fn get_certificate_data_for_domain(domain: &str) {
    // Connect to the server
    let stream = match TcpStream::connect(format!("{domain}{}",":443")) {
        Ok(stream) => stream,
        Err(e) => panic!("{}", format!("{:?}", e.to_string())) 
    };

    // Create an SSL connector
    let mut connector = SslConnector::builder(SslMethod::tls()).unwrap();
    connector.set_verify(openssl::ssl::SslVerifyMode::PEER);

    // Connect the SSL stream to the server
    let ssl = connector.build().configure().unwrap().connect(domain, stream).expect("Failed to establish SSL connection");
    
    // Get the certificate chain
    let cert_chain = ssl.ssl().peer_cert_chain().unwrap();

    // Print the certificates
    for (i, cert) in cert_chain.iter().enumerate() {
        let certificate_type = match i {
            0 => "Leaf Certificate",
            1 => "Intermediate Certificate",
            2 => "Root Certificate",
            _ => "Certificate",
        };
        println!("{}", certificate_type);
        
        println!("{:?}", cert.subject_name());
        println!("{:?}", cert.not_before());
        println!("{:?}", cert.not_after());
        println!("{:?} \n ", openssl::base64::encode_block(openssl::sha::sha256(cert.public_key().unwrap().as_ref().public_key_to_der().unwrap().as_slice()).as_slice()));
    }
}
