use std::error::Error;
use std::net::UdpSocket;
use std::thread;
use smart_dns::*;
use std::sync::Arc;

fn main() ->Result<(),Box<dyn Error>> {
    // Bind an UDP socket on port 2053
    let socket = Arc::new(UdpSocket::bind(("0.0.0.0", 53))?);

    loop {
        let mut req_buffer = core_dns::BytePacketBuffer::new();
        match socket.recv_from(&mut req_buffer.buf) {
            Ok((_,addr)) => {
                let socket_clone = socket.clone();
                thread::spawn(move || {
                    match core_dns::handle_query(socket_clone,addr,req_buffer) {
                        Ok(_) => {},
                        Err(e) => println!("Err: {}",e),
                    }
                });
            },
            Err(e) => {
                println!("socks recv from err: {}",e);
            }
        }
    }
}
