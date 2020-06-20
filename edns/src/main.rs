use std::error::Error;
use std::net::UdpSocket;
use edns::*;

fn main() -> Result<(),Box<dyn Error>> {
    let socket = UdpSocket::bind(("0.0.0.0", 2053))?;

    loop {
        match pdns::handle_query(&socket) {
            Ok(_) => {},
            Err(e) => eprintln!("An error occured: {}", e),
        }
    }
}