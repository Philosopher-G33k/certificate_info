mod config;

use openssl::ssl::{SslConnector, SslMethod};
use std::net::TcpStream;

use clap::Parser;

pub fn run() {
    get_args();
}

fn get_args() {
    let config = config::config::Config::parse();
    println!("{}", config.domain);
    get_certificate_data_for_domain(&config.domain);
}

fn get_certificate_data_for_domain(domain: &str) {
    // "dsp-mauth-dbb.business.hsbc.co.uk:443"
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
        println!("Certificate {}:", i+1);
        //println!("{:?}", cert.public_key().unwrap().as_ref().public_key_to_der().unwrap().as_slice());
        println!("{:?}", cert.subject_name());
        println!("{:?}", cert.not_before());
        println!("{:?}", cert.not_after());
        println!("{:?} \n ", openssl::base64::encode_block(openssl::sha::sha256(cert.public_key().unwrap().as_ref().public_key_to_der().unwrap().as_slice()).as_slice()));
    }
}
