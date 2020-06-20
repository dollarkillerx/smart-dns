use std::{
    error::Error,
    fs::File,
    io::Read,
    net::UdpSocket,
};
use try_dns::*;

// # Putting it all together
// 让我们使用我们之前生成的response_packet.txt进行尝试！
fn main() -> Result<(),Box<dyn Error>> {
    // test1()?;

    // test2()?;
    test3()?;

    Ok(())
}

fn test1() -> Result<(),Box<dyn Error>> {
    let mut f = File::open("response_packet.txt")?;
    let mut buffer = parser::BytePacketBuffer::new();
    f.read(&mut buffer.buf)?;

    let packet = parser::DnsPacket::from_buffer(&mut buffer)?;
    println!("{:#?}", packet.header);

    for q in packet.questions {
        println!("{:#?}", q);
    }
    for rec in packet.answers {
        println!("{:#?}", rec);
    }
    for rec in packet.authorities {
        println!("{:#?}", rec);
    }
    for rec in packet.resources {
        println!("{:#?}", rec);
    }

    Ok(())
}

fn test2() -> Result<(),Box<dyn Error>> {
    // Perform an A query for google.com
    // let qname = "www.baidu.com";
    // let qtype = parser::QueryType::A;

    let qname = "yahoo.com";
    let qtype = parser::QueryType::MX;

    // Using googles public DNS server
    let server = ("8.8.8.8", 53);

    // Bind a UDP socket to an arbitrary port
    let socket = UdpSocket::bind(("0.0.0.0", 43210))?;

    // Build our query packet. It's important that we remember to set the
    // `recursion_desired` flag. As noted earlier, the packet id is arbitrary.
    let mut packet = parser::DnsPacket::new();

    packet.header.id = 6666;
    packet.header.questions = 1;
    packet.header.recursion_desired = true;
    packet
        .questions
        .push(parser::DnsQuestion::new(qname.to_string(), qtype));

    // Use our new write method to write the packet to a buffer...
    let mut req_buffer = parser::BytePacketBuffer::new();
    packet.write(&mut req_buffer)?;

    // ...and send it off to the server using our socket:
    socket.send_to(&req_buffer.buf[0..req_buffer.pos], server)?;

    // To prepare for receiving the response, we'll create a new `BytePacketBuffer`,
    // and ask the socket to write the response directly into our buffer.
    let mut res_buffer = parser::BytePacketBuffer::new();
    socket.recv_from(&mut res_buffer.buf)?;

    // As per the previous section, `DnsPacket::from_buffer()` is then used to
    // actually parse the packet after which we can print the response.
    let res_packet = parser::DnsPacket::from_buffer(&mut res_buffer)?;
    println!("{:#?}", res_packet.header);

    for q in res_packet.questions {
        println!("{:#?}", q);
    }
    for rec in res_packet.answers {
        println!("{:#?}", rec);
    }
    for rec in res_packet.authorities {
        println!("{:#?}", rec);
    }
    for rec in res_packet.resources {
        println!("{:#?}", rec);
    }

    Ok(())
}

fn test3() -> Result<(),Box<dyn Error>> {
    // Bind an UDP socket on port 2053
    let socket = UdpSocket::bind(("0.0.0.0", 2053))?;

    // For now, queries are handled sequentially, so an infinite loop for servicing
    // requests is initiated.
    loop {
        match parser::handle_query(&socket) {
            Ok(_) => {},
            Err(e) => eprintln!("An error occured: {}", e),
        }
    }
}