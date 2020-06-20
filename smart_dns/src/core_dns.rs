use std::error::Error;
use std::net::{Ipv4Addr, Ipv6Addr, UdpSocket, SocketAddr};
use std::sync::Arc;

pub struct BytePacketBuffer {
    pub buf: [u8; 512],
    pub pos: usize, // 当前读取到的位置
}

impl BytePacketBuffer {
    pub fn new() -> BytePacketBuffer {
        BytePacketBuffer {
            buf: [0; 512],
            pos: 0,
        }
    }

    // 缓冲区内的当前位置
    fn pos(&self) -> usize {
        self.pos
    }

    // 将缓冲区位置向前步进特定的步数
    fn step(&mut self, steps: usize) -> Result<(), Box<dyn Error>> {
        self.pos += steps;
        Ok(())
    }

    // 更改缓冲区位置
    fn seek(&mut self, pos: usize) -> Result<(), Box<dyn Error>> {
        self.pos = pos;
        Ok(())
    }

    // 读取一个字节并将位置向前移动一步
    fn read(&mut self) -> Result<u8, Box<dyn Error>> {
        if self.pos > 512 {
            return Err("End of buffer".into());
        }
        let res = self.buf[self.pos];
        self.pos += 1;
        Ok(res)
    }

    // 获取单个字节，而不更改缓冲区位置
    fn get(&mut self, pos: usize) -> Result<u8, Box<dyn Error>> {
        if pos >= 512 {
            return Err("End of buffer".into());
        }

        Ok(self.buf[pos])
    }

    // 获取一个字节范围
    fn get_range(&mut self, start: usize, len: usize) -> Result<&[u8], Box<dyn Error>> {
        if start + len >= 512 {
            return Err("End of buffer".into());
        }
        Ok(&self.buf[start..start + len as usize])
    }

    // 读取两个字节，向前迈出两步
    fn read_u16(&mut self) -> Result<u16, Box<dyn Error>> {
        let res = ((self.read()? as u16) << 8) | (self.read()? as u16);

        Ok(res)
    }

    // 读取四个字节，前进四步
    fn read_u32(&mut self) -> Result<u32, Box<dyn Error>> {
        let res = ((self.read()? as u32) << 24)
            | ((self.read()? as u32) << 16)
            | ((self.read()? as u32) << 8)
            | ((self.read()? as u32) << 0);

        Ok(res)
    }

    // Read a qname
    // 棘手的部分：读取域名，并考虑标签。
    // 将采用[3] www [6] google [3] com [0]之类的内容并附加
    // www.google.com to outstr.
    fn read_qname(&mut self, outstr: &mut String) -> Result<(), Box<dyn Error>> {
        // 由于我们可能会遇到跳跃，因此我们将跟踪自己的位置本地使用，而不是使用结构中的位置。
        // 这使我们可以将共同的立场移动到当前立场之上 qname，同时跟踪当前qname的进度使用此变量。
        let mut pos = self.pos;

        // 追踪我们是否跳了 track whether or not we've jumped
        let mut jumped = false;
        let max_jumps = 5;
        let mut jumps_performed = 0;

        // 我们为每个标签附加的定界符。由于我们不希望在域名的开头加点，因此我们暂时将其保留为
        // 空并将其设置为“”。 在第一次迭代结束时。
        let mut delim = "";
        loop {
            // Dns数据包是不受信任的数据，因此我们需要保持偏执。
            // 有人可以在跳转指令中循环制作一个数据包。
            // 这可以防止此类数据包。
            // (防止恶意数据包触发无限循环)
            if jumps_performed > max_jumps {
                return Err(format!("Limit of {} jumps exceeded", max_jumps).into());
            }

            // 在这一点上，我们始终处在标签的开头。
            // 回想一下，标签以长度字节开头。
            let len = self.get(pos)?;

            // 如果len的最高两位被置位，则表示跳到数据包中的其他一些偏移量：
            if (len & 0xC0) == 0xC0 {
                // 将缓冲区位置更新到当前标签之后的位置。 我们不需要再碰它了。
                if !jumped {
                    self.seek(pos + 2)?;
                }

                // 读取另一个字节，计算偏移量，并通过更新本地位置变量执行跳转
                let b2 = self.get(pos + 1)? as u16;
                let offset = (((len as u16) ^ 0xC0) << 8) | b2;
                pos = offset as usize;

                // 表示执行了跳转。
                jumped = true;
                jumps_performed += 1;

                continue;
            }
            // 基本方案，我们正在读取一个标签并将其附加到输出：
            else {
                // 向前移动一个字节以超过长度字节。
                pos += 1;
                // 域名以长度为0的空标签终止，所以如果长度为零，我们就完成了。
                if len == 0 {
                    break;
                }
                // 首先将定界符追加到我们的输出缓冲区。
                outstr.push_str(delim);

                // 提取此标签的实际ASCII字节并将其附加到输出缓冲区。
                let str_buffer = self.get_range(pos, len as usize)?;
                outstr.push_str(&String::from_utf8_lossy(str_buffer).to_lowercase());

                delim = ".";

                // 向前移动标签的全长
                pos += len as usize;
            }
        }

        if !jumped {
            self.seek(pos)?;
        }

        Ok(())
    }

    // # transmitter dns
    fn write(&mut self,val: u8) -> Result<(),Box<dyn Error>> {
        if self.pos >= 512 {
            return Err("End of buffer".into())
        }
        self.buf[self.pos] = val;
        self.pos += 1;
        Ok(())
    }
    fn write_u8(&mut self,val: u8) -> Result<(),Box<dyn Error>> {
        self.write(val)?;

        Ok(())
    }
    fn write_u16(&mut self,val: u16) -> Result<(),Box<dyn Error>> {
        self.write( (val >> 8) as u8 )?;
        self.write( (val & 0xFF) as u8 )?;

        Ok(())
    }
    fn write_u32(&mut self, val: u32) -> Result<(),Box<dyn Error>> {
        self.write(((val >> 24) & 0xFF) as u8)?;
        self.write(((val >> 16) & 0xFF) as u8)?;
        self.write(((val >> 8) & 0xFF) as u8)?;
        self.write(((val >> 0) & 0xFF) as u8)?;

        Ok(())
    }

    // 我们还需要一个函数以标签形式编写查询名称：
    fn write_qname(&mut self,qname: &str) -> Result<(),Box<dyn Error>> {
        for label in qname.split('.') {
            let len = label.len();
            if len > 0x34 {
                return Err("Single label exceeds 63 characters of length".into());
            }

            self.write_u8(len as u8)?;
            for b in label.as_bytes() {
                self.write_u8(*b)?;
            }
        }

        self.write_u8(0)?;
        Ok(())
    }

    // add type
    fn set(&mut self, pos: usize, val: u8) -> Result<(),Box<dyn Error>> {
        self.buf[pos] = val;

        Ok(())
    }

    fn set_u16(&mut self, pos: usize, val: u16) -> Result<(),Box<dyn Error>> {
        self.set(pos, (val >> 8) as u8)?;
        self.set(pos + 1, (val & 0xFF) as u8)?;

        Ok(())
    }
}

// # ResultCode
// 在转到标题之前，我们将为rescode字段的值添加一个枚举
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ResultCode {
    NOERROR = 0,
    FORMERR = 1,
    SERVFAIL = 2,
    NXDOMAIN = 3,
    NOTIMP = 4,
    REFUSED = 5,
}

impl ResultCode {
    pub fn from_num(num: u8) -> ResultCode {
        match num {
            1 => ResultCode::FORMERR,
            2 => ResultCode::SERVFAIL,
            3 => ResultCode::NXDOMAIN,
            4 => ResultCode::NOTIMP,
            5 => ResultCode::REFUSED,
            0 | _ => ResultCode::NOERROR,
        }
    }
}

// # DnsHeader
// 现在我们可以开始处理标题了。我们将这样表示：
#[derive(Clone, Debug)]
pub struct DnsHeader {
    pub id: u16, // 16 bits

    pub recursion_desired: bool,
    // 1 bit
    pub truncated_message: bool,
    // 1 bit
    pub authoritative_answer: bool,
    // 1 bit
    pub opcode: u8,
    // 4 bits
    pub response: bool,             // 1 bit

    pub rescode: ResultCode,
    // 4 bits
    pub checking_disabled: bool,
    // 1 bit
    pub authed_data: bool,
    // 1 bit
    pub z: bool,
    // 1 bit
    pub recursion_available: bool, // 1 bit

    pub questions: u16,
    // 16 bits
    pub answers: u16,
    // 16 bits
    pub authoritative_entries: u16,
    // 16 bits
    pub resource_entries: u16,      // 16 bits
}
// 该实现涉及很多琐事：
impl DnsHeader {
    pub fn new() -> DnsHeader {
        DnsHeader {
            id: 0,

            recursion_desired: false,
            truncated_message: false,
            authoritative_answer: false,
            opcode: 0,
            response: false,

            rescode: ResultCode::NOERROR,
            checking_disabled: false,
            authed_data: false,
            z: false,
            recursion_available: false,

            questions: 0,
            answers: 0,
            authoritative_entries: 0,
            resource_entries: 0,
        }
    }

    pub fn read(&mut self, buffer: &mut BytePacketBuffer) -> Result<(), Box<dyn Error>> {
        self.id = buffer.read_u16()?;

        let flags = buffer.read_u16()?;
        let a = (flags >> 8) as u8;
        let b = (flags & 0xFF) as u8;

        self.recursion_desired = (a & (1 << 0)) > 0;
        self.truncated_message = (a & (1 << 1)) > 0;
        self.authoritative_answer = (a & (1 << 2)) > 0;
        self.opcode = (a >> 3) & 0x0F;
        self.response = (a & (1 << 7)) > 0;

        self.rescode = ResultCode::from_num(b & 0x0F);
        self.checking_disabled = (b & (1 << 4)) > 0;
        self.authed_data = (b & (1 << 5)) > 0;
        self.z = (b & (1 << 6)) > 0;
        self.recursion_available = (b & (1 << 7)) > 0;

        self.questions = buffer.read_u16()?;
        self.answers = buffer.read_u16()?;
        self.authoritative_entries = buffer.read_u16()?;
        self.resource_entries = buffer.read_u16()?;

        // Return the constant header size
        Ok(())
    }

    // # 扩展DnsHeader以进行编写
    // 基于我们的新功能，我们可以扩展协议表示结构。从DnsHeader开始：
    pub fn write(&self,buffer: &mut BytePacketBuffer) -> Result<(),Box<dyn Error>> {
        buffer.write_u16(self.id)?;

        buffer.write_u8(
            (self.recursion_desired as u8)
                | ((self.truncated_message as u8) << 1)
                | ((self.authoritative_answer as u8) << 2)
                | (self.opcode << 3)
                | ((self.response as u8) << 7) as u8,
        )?;

        buffer.write_u8(
            (self.rescode as u8)
                | ((self.checking_disabled as u8) << 4)
                | ((self.authed_data as u8) << 5)
                | ((self.z as u8) << 6)
                | ((self.recursion_available as u8) << 7),
        )?;

        buffer.write_u16(self.questions)?;
        buffer.write_u16(self.answers)?;
        buffer.write_u16(self.authoritative_entries)?;
        buffer.write_u16(self.resource_entries)?;

        Ok(())
    }

}

// # QueryType
// 在继续讨论数据包的问题部分之前，我们需要一种表示要查询的记录类型的方法：
#[derive(PartialEq, Eq, Debug, Clone, Hash, Copy)]
pub enum QueryType {
    UNKNOWN(u16),
    A, // 1
    NS,    // 2
    CNAME, // 5
    MX,    // 15
    AAAA,  // 28
}
impl QueryType {
    pub fn to_num(&self) -> u16 {
        match *self {
            QueryType::UNKNOWN(x) => x,
            QueryType::A => 1,
            QueryType::NS => 2,
            QueryType::CNAME => 5,
            QueryType::MX => 15,
            QueryType::AAAA => 28,
        }
    }

    pub fn from_num(num: u16) -> QueryType {
        match num {
            1 => QueryType::A,
            2 => QueryType::NS,
            5 => QueryType::CNAME,
            15 => QueryType::MX,
            28 => QueryType::AAAA,
            _ => QueryType::UNKNOWN(num),
        }
    }
}

// # DnsQuestion
// 枚举使我们以后可以轻松添加更多记录类型。现在输入问题：
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuestion {
    pub name: String,
    pub qtype: QueryType,
}
impl DnsQuestion {
    pub fn new(name: String, qtype: QueryType) -> DnsQuestion {
        DnsQuestion {
            name: name,
            qtype: qtype,
        }
    }
    // 作为BytePacketBuffer结构的一部分，完成了读取域名的艰苦工作后，事实证明它非常紧凑。
    pub fn read(&mut self,buffer: &mut BytePacketBuffer) -> Result<(),Box<dyn Error>> {
        buffer.read_qname(&mut self.name)?;
        self.qtype = QueryType::from_num(buffer.read_u16()?);
        let _ = buffer.read_u16()?;

        Ok(())
    }

    pub fn write(&self,buffer: &mut BytePacketBuffer) -> Result<(),Box<dyn Error>> {
        buffer.write_qname(&self.name)?;

        let typenum = self.qtype.to_num();
        buffer.write_u16(typenum)?;
        buffer.write_u16(1)?;

        Ok(())
    }
}

// # DnsRecord
// 显然，我们还将需要一种表示实际dns记录的方式，并且我们将再次使用一个枚举来轻松扩展：
#[derive(Debug,Clone,Eq, PartialEq,Hash,PartialOrd,Ord)]
pub enum DnsRecord {
    UNKNOWN {
        domain: String,
        qtype: u16,
        data_len: u16,
        ttl: u32,
    }, // 0
    A {
        domain: String,
        addr: Ipv4Addr,
        ttl: u32,
    }, // 1
    NS {
        domain: String,
        host: String,
        ttl: u32,
    }, // 2
    CNAME {
        domain: String,
        host: String,
        ttl: u32,
    }, // 5
    MX {
        domain: String,
        priority: u16,
        host: String,
        ttl: u32,
    }, // 15
    AAAA {
        domain: String,
        addr: Ipv6Addr,
        ttl: u32,
    }, // 28
}
// 由于记录的类型很多，我们将添加跟踪尚未遇到的记录类型的功能。
// 枚举还使我们以后可以轻松添加新记录。 DnsRecord的实际实现如下所示：
impl DnsRecord {
    pub fn read(buffer: &mut BytePacketBuffer) -> Result<DnsRecord,Box<dyn Error>> {
        let mut domain = String::new();
        buffer.read_qname(&mut domain)?;

        let qtype_num = buffer.read_u16()?;
        let qtype = QueryType::from_num(qtype_num);
        let _ = buffer.read_u16()?;
        let ttl = buffer.read_u32()?;
        let data_len = buffer.read_u16()?;

        match qtype {
            QueryType::A => {
                let raw_addr = buffer.read_u32()?;
                let addr = Ipv4Addr::new(
                    ((raw_addr >> 24) & 0xFF) as u8,
                    ((raw_addr >> 16) & 0xFF) as u8,
                    ((raw_addr >> 8) & 0xFF) as u8,
                    ((raw_addr >> 0) & 0xFF) as u8,
                );

                Ok(DnsRecord::A {
                    domain: domain,
                    addr: addr,
                    ttl: ttl,
                })
            }
            QueryType::AAAA => {
                let raw_addr1 = buffer.read_u32()?;
                let raw_addr2 = buffer.read_u32()?;
                let raw_addr3 = buffer.read_u32()?;
                let raw_addr4 = buffer.read_u32()?;
                let addr = Ipv6Addr::new(
                    ((raw_addr1 >> 16) & 0xFFFF) as u16,
                    ((raw_addr1 >> 0) & 0xFFFF) as u16,
                    ((raw_addr2 >> 16) & 0xFFFF) as u16,
                    ((raw_addr2 >> 0) & 0xFFFF) as u16,
                    ((raw_addr3 >> 16) & 0xFFFF) as u16,
                    ((raw_addr3 >> 0) & 0xFFFF) as u16,
                    ((raw_addr4 >> 16) & 0xFFFF) as u16,
                    ((raw_addr4 >> 0) & 0xFFFF) as u16,
                );

                Ok(DnsRecord::AAAA {
                    domain: domain,
                    addr: addr,
                    ttl: ttl,
                })
            }
            QueryType::NS => {
                let mut ns = String::new();
                buffer.read_qname(&mut ns)?;

                Ok(DnsRecord::NS {
                    domain: domain,
                    host: ns,
                    ttl: ttl,
                })
            }
            QueryType::CNAME => {
                let mut cname = String::new();
                buffer.read_qname(&mut cname)?;

                Ok(DnsRecord::CNAME {
                    domain: domain,
                    host: cname,
                    ttl: ttl,
                })
            }
            QueryType::MX => {
                let priority = buffer.read_u16()?;
                let mut mx = String::new();
                buffer.read_qname(&mut mx)?;

                Ok(DnsRecord::MX {
                    domain: domain,
                    priority: priority,
                    host: mx,
                    ttl: ttl,
                })
            }
            QueryType::UNKNOWN(_) => {
                buffer.step(data_len as usize)?;

                Ok(DnsRecord::UNKNOWN {
                    domain: domain,
                    qtype: qtype_num,
                    data_len: data_len,
                    ttl: ttl,
                })
            }
        }
    }
    // DnsRecord现在也非常紧凑，尽管我们最终将在此处添加很多代码来处理不同的记录类型
    pub fn write(&self, buffer: &mut BytePacketBuffer) -> Result<usize,Box<dyn Error>> {
        let start_pos = buffer.pos();

        match *self {
            DnsRecord::A {
                ref domain,
                ref addr,
                ttl,
            } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::A.to_num())?;
                buffer.write_u16(1)?;
                buffer.write_u32(ttl)?;
                buffer.write_u16(4)?;

                let octets = addr.octets();
                buffer.write_u8(octets[0])?;
                buffer.write_u8(octets[1])?;
                buffer.write_u8(octets[2])?;
                buffer.write_u8(octets[3])?;
            }
            DnsRecord::NS {
                ref domain,
                ref host,
                ttl,
            } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::NS.to_num())?;
                buffer.write_u16(1)?;
                buffer.write_u32(ttl)?;

                let pos = buffer.pos();
                buffer.write_u16(0)?;

                buffer.write_qname(host)?;

                let size = buffer.pos() - (pos + 2);
                buffer.set_u16(pos, size as u16)?;
            }
            DnsRecord::CNAME {
                ref domain,
                ref host,
                ttl,
            } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::CNAME.to_num())?;
                buffer.write_u16(1)?;
                buffer.write_u32(ttl)?;

                let pos = buffer.pos();
                buffer.write_u16(0)?;

                buffer.write_qname(host)?;

                let size = buffer.pos() - (pos + 2);
                buffer.set_u16(pos, size as u16)?;
            }
            DnsRecord::MX {
                ref domain,
                priority,
                ref host,
                ttl,
            } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::MX.to_num())?;
                buffer.write_u16(1)?;
                buffer.write_u32(ttl)?;

                let pos = buffer.pos();
                buffer.write_u16(0)?;

                buffer.write_u16(priority)?;
                buffer.write_qname(host)?;

                let size = buffer.pos() - (pos + 2);
                buffer.set_u16(pos, size as u16)?;
            }
            DnsRecord::AAAA {
                ref domain,
                ref addr,
                ttl,
            } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::AAAA.to_num())?;
                buffer.write_u16(1)?;
                buffer.write_u32(ttl)?;
                buffer.write_u16(16)?;

                for octet in &addr.segments() {
                    buffer.write_u16(*octet)?;
                }
            }
            DnsRecord::UNKNOWN { .. } => {
                println!("Skipping record: {:?}", self);
            }
        }

        Ok(buffer.pos() - start_pos)
    }
}

// # DnsPacket
// 最后，让我们将它们放到一个称为DnsPacket的结构中：
#[derive(Clone, Debug)]
pub struct DnsPacket {
    pub header: DnsHeader,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsRecord>,
    pub authorities: Vec<DnsRecord>,
    pub resources: Vec<DnsRecord>,
}

impl DnsPacket {
    pub fn new() -> DnsPacket {
        DnsPacket {
            header: DnsHeader::new(),
            questions: Vec::new(),
            answers: Vec::new(),
            authorities: Vec::new(),
            resources: Vec::new(),
        }
    }

    pub fn from_buffer(buffer: &mut BytePacketBuffer) -> Result<DnsPacket,Box<dyn Error>> {
        let mut result = DnsPacket::new();
        result.header.read(buffer)?;

        for _ in 0..result.header.questions {
            let mut question = DnsQuestion::new("".to_string(), QueryType::UNKNOWN(0));
            question.read(buffer)?;
            result.questions.push(question);
        }

        for _ in 0..result.header.answers {
            let rec = DnsRecord::read(buffer)?;
            result.answers.push(rec);
        }
        for _ in 0..result.header.authoritative_entries {
            let rec = DnsRecord::read(buffer)?;
            result.authorities.push(rec);
        }
        for _ in 0..result.header.resource_entries {
            let rec = DnsRecord::read(buffer)?;
            result.resources.push(rec);
        }

        Ok(result)
    }


    pub fn write(&mut self, buffer: &mut BytePacketBuffer) -> Result<(),Box<dyn Error>> {
        self.header.questions = self.questions.len() as u16;
        self.header.answers = self.answers.len() as u16;
        self.header.authoritative_entries = self.authorities.len() as u16;
        self.header.resource_entries = self.resources.len() as u16;

        self.header.write(buffer)?;

        for question in &self.questions {
            question.write(buffer)?;
        }
        for rec in &self.answers {
            rec.write(buffer)?;
        }
        for rec in &self.authorities {
            rec.write(buffer)?;
        }
        for rec in &self.resources {
            rec.write(buffer)?;
        }

        Ok(())
    }

}

// # Lookup
pub fn lookup(qname: &str,qtype: QueryType) -> Result<DnsPacket,Box<dyn Error>> {
    let server = ("8.8.8.8", 53);

    let socket = UdpSocket::bind(("0.0.0.0", 43210))?;

    let mut packet = DnsPacket::new();

    packet.header.id = 6666;
    packet.header.questions = 1;
    packet.header.recursion_desired = true;
    packet
        .questions
        .push(DnsQuestion::new(qname.to_string(), qtype));

    let mut req_buffer = BytePacketBuffer::new();
    packet.write(&mut req_buffer)?;
    socket.send_to(&req_buffer.buf[0..req_buffer.pos], server)?;

    let mut res_buffer = BytePacketBuffer::new();
    socket.recv_from(&mut res_buffer.buf)?;

    DnsPacket::from_buffer(&mut res_buffer)
}

/// Handle a single incoming packet
pub fn handle_query(socket: Arc<UdpSocket>, src: SocketAddr, mut req_buffer: BytePacketBuffer) -> Result<(),Box<dyn Error>> {
    // Next, `DnsPacket::from_buffer` is used to parse the raw bytes into
    // a `DnsPacket`.
    let mut request = DnsPacket::from_buffer(&mut req_buffer)?;

    // Create and initialize the response packet
    let mut packet = DnsPacket::new();
    packet.header.id = request.header.id;
    packet.header.recursion_desired = true;
    packet.header.recursion_available = true;
    packet.header.response = true;

    // In the normal case, exactly one question is present
    if let Some(question) = request.questions.pop() {
        println!("Received query: {:?}", question);

        // Since all is set up and as expected, the query can be forwarded to the
        // target server. There's always the possibility that the query will
        // fail, in which case the `SERVFAIL` response code is set to indicate
        // as much to the client. If rather everything goes as planned, the
        // question and response records as copied into our response packet.
        if let Ok(result) = lookup(&question.name, question.qtype) {
            packet.questions.push(question);
            packet.header.rescode = result.header.rescode;

            for rec in result.answers {
                println!("Answer: {:?}", rec);
                packet.answers.push(rec);
            }
            for rec in result.authorities {
                println!("Authority: {:?}", rec);
                packet.authorities.push(rec);
            }
            for rec in result.resources {
                println!("Resource: {:?}", rec);
                packet.resources.push(rec);
            }
        } else {
            packet.header.rescode = ResultCode::SERVFAIL;
        }
    }
    // Being mindful of how unreliable input data from arbitrary senders can be, we
    // need make sure that a question is actually present. If not, we return `FORMERR`
    // to indicate that the sender made something wrong.
    else {
        packet.header.rescode = ResultCode::FORMERR;
    }

    // The only thing remaining is to encode our response and send it off!
    let mut res_buffer = BytePacketBuffer::new();
    packet.write(&mut res_buffer)?;

    let len = res_buffer.pos();
    let data = res_buffer.get_range(0, len)?;

    socket.send_to(data, src)?;

    Ok(())
}