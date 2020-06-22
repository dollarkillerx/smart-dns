use std::error::Error;
use std::net::UdpSocket;
use std::thread;
use smart_dns::*;
use std::sync::Arc;

fn main() ->Result<(),Box<dyn Error>> {
<<<<<<< HEAD
    // Bind an UDP socket on port 2053
=======
    // Bind an UDP socket on port 53  (53需要root权限)
>>>>>>> 68e69611247edb77b271d1e993329fda9ecf635b
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
