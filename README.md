# Smart DNS
Smart Dns RUST实现智能DNS  对标Dnspod

### 分支
- try 
- dev 
- master 

## DNS protocol  DNS协议基础理论
> DNS using UDP limited to 512 bytes

| Section            | Size     | Type              | Purpose                                                                                                |
| ------------------ | -------- | ----------------- | ------------------------------------------------------------------------------------------------------ |
| Header             | 12 Bytes | Header            | 有关查询/响应的信息。                                                                                      |
| Question Section   | Variable | List of Questions | 查询名称（domain） 和感兴趣的记录类型                                                                        |
| Answer Section     | Variable | List of Records   | 请求类型的相关记录。                                                                                       |
| Authority Section  | Variable | List of Records   | 名称服务器列表（NS记录），用于递归解决查询。                                                                   |
| 附加部分            | Variable | List of Records   | 其他记录，可能会有用。例如，NS记录对应的A记录。                                                                 |

本质上，我们必须支持三个不同的对象：标头，问题和记录。方便地，记录和问题列表只是简单地附加在一行中的单个实例，没有多余的内容。标头中提供了每个节中的记录数。标头结构如下所示：

| RFC Name | Descriptive Name     | Length             | Description                                                                                                                                                                         |
| -------- | -------------------- | ------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| ID       | Packet Identifier    | 16 bits            | 查询 && 相应 因具有相同的ID  应为DNS是无状态的                                                                                                                                            |
| QR       | Query Response       | 1 bit              | 0 for 查询, 1 for 相应.                                                                                                                                                              |
| OPCODE   | Operation Code       | 4 bits             | 通常始终为0，有关详细信息，请参阅RFC1035。                                                                                                                                                |
| AA       | Authoritative Answer | 1 bit              | 如果响应服务器是权威服务器，即设置为“拥有”，则设置为1。                                                                                                                                      |
| TC       | Truncated Message    | 1 bit              | 如果消息长度超过512个字节，则设置为1。传统上暗示可以使用TCP重新发出查询，但长度限制不适用。                                                                                                        |
| RD       | Recursion Desired    | 1 bit              | 如果服务器在没有可用答案的情况下尝试递归解决查询，则由请求的发送者设置。                                                                                                                         |
| RA       | Recursion Available  | 1 bit              | 由服务器设置以指示是否允许递归查询。                                                                                                                                                      |
| Z        | Reserved             | 3 bits             | 最初保留供以后使用，但现在用于DNSSEC查询。                                                                                                                                                |
| RCODE    | Response Code        | 4 bits             | 由服务器设置以指示响应的状态，即响应是成功还是失败，并在后一种情况下提供有关失败原因的详细信息。                                                                                                      |
| QDCOUNT  | Question Count       | 16 bits            | 问题部分中的条目数                                                                                                                                     |
| ANCOUNT  | Answer Count         | 16 bits            | 答案部分中的条目数                                                                                                                                        |
| NSCOUNT  | Authority Count      | 16 bits            | 权限部分中的条目数                                                                                                                                    |
| ARCOUNT  | Additional Count     | 16 bits            | 附加部分中的条目数                                                                                                                                   |

question  DNS 请求部分 proto

| Field  | Type           | Description                                                          |
| ------ | -------------- | -------------------------------------------------------------------- |
| Name   | Label Sequence | 域名，编码为标签序列，如下所述。 |
| Type   | 2-byte Integer | 记录类型。                                                   |
| Class  | 2-byte Integer | 实际上，该类始终设置为1。                             |

The tricky part lies in the encoding of the domain name, which we'll return to
later.

Finally, we've got the records which are the meat of the protocol. Many record
types exists, but for now we'll only consider a few essential. All records have
the following preamble:

| Field  | Type           | Description                                                                       |
| ------ | -------------- | --------------------------------------------------------------------------------- |
| Name   | Label Sequence | 域名，编码为标签序列，如下所述。             |
| Type   | 2-byte Integer | 记录类型。                                                                 |
| Class  | 2-byte Integer | 实际上，该类始终设置为1。                                          |
| TTL    | 4-byte Integer | 生存时间，即可以重新查询记录之前将其缓存多长时间。 |
| Len    | 2-byte Integer | 记录类型特定数据的长度。                                          |

现在我们已经准备好要查看特定的记录类型，我们将从最基本的记录开始：A记录，将名称映射到ip。

| Field      | Type            | Description                                                                       |
| ---------- | --------------- | --------------------------------------------------------------------------------- |
| Preamble   | Record Preamble | 如上所述，长度字段设置为4的记录前导。          |
| IP         | 4-byte Integer  | 编码为四字节整数的IP地址。                                      |

到此为止，让我们在实践中通过使用dig工具执行查找来感受一下：
```shell script
wangy@mv-ubuntu-006:~$ dig +noedns google.com

; <<>> DiG 9.11.3-1ubuntu1.12-Ubuntu <<>> +noedns google.com
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 57398
;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;google.com.			IN	A

;; ANSWER SECTION:
google.com.		599	IN	A	46.82.174.69

;; Query time: 4 msec
;; SERVER: 127.0.0.53#53(127.0.0.53)
;; WHEN: Fri Jun 19 17:26:28 CST 2020
;; MSG SIZE  rcvd: 44
```

### DNS记录类型
- `A` 地址记录（Address），返回域名指向的IP地址。
- `NS` 域名服务器记录（Name Server），返回保存下一级域名信息的服务器地址。该记录只能设置为域名，不能设置为IP地址。
- `MX` 邮件记录（Mail eXchange），返回接收电子邮件的服务器地址。
- `CNAME` 规范名称记录（Canonical Name），返回另一个域名，即当前查询的域名是另一个域名的跳转，详见下文。
- `PTR` 逆向查询记录（Pointer Record），只用于从IP地址查询域名，详见下文。 `PTR记录用于从IP地址反查域名。dig命令的-x参数用于查询PTR记录  dig -x 192.30.252.153`

我们正在使用+ noedns标志来确保我们坚持原始格式。上面的输出中有一些注意事项：
- 我们可以看到dig明确描述了响应数据包的标头，问题和答案部分。
- 标头使用的OPCODE QUERY对应于0。状态（RESCODE）设置为NOERROR，其数值为0。
ID为57398，并且会随着重复的查询而随机更改。启用查询响应（qr），所需的递归（rd），可用的递归（ra）标志，这些标志的数值为1。
我们现在可以忽略`ad`，因为它与DNSSEC有关。最后，标题告诉我们有一个问题和一个答案记录。
- 问题部分向我们显示了我们的问题，其中IN表示类，A告诉我们我们正在查询A记录。
- 答案部分包含答案记录以及Google的IP。 204是TTL，IN再次是类，A是记录类型。最后，我们有了google.com的IP地址。
- 最后一行告诉我们，总包大小为44个字节。

不过，这里仍然有一些细节被遮挡，因此让我们更深入地研究一下数据包的十六进制转储。我们可以使用netcat侦听端口，然后直接dig将查询发送到该端口。在一个终端窗口中，我们运行：
```shell script 
# nc -u -l 1053 > query_packet.txt

query:

# dig +retry=0 -p 1053 @127.0.0.1 +noedns google.com
```
我们也可以使用查询包来记录响应包：
```shell script 
# nc -u 8.8.8.8 53 < query_packet.txt > response_packet.txt
```
稍等一下，然后使用Ctrl + C取消。现在，我们准备检查我们的数据包：
```shell script
xxx@mv-ubuntu-006:$ hexdump -C query_packet.txt 
00000000  29 9a 01 20 00 01 00 00  00 00 00 00 06 67 6f 6f  |).. .........goo|
00000010  67 6c 65 03 63 6f 6d 00  00 01 00 01              |gle.com.....|
0000001c

xxx@mv-ubuntu-006:$ hexdump -C response_packet.txt 
00000000  29 9a 85 80 00 01 00 01  00 00 00 00 06 67 6f 6f  |)............goo|
00000010  67 6c 65 03 63 6f 6d 00  00 01 00 01 06 67 6f 6f  |gle.com......goo|
00000020  67 6c 65 03 63 6f 6d 00  00 01 00 01 00 00 00 3c  |gle.com........<|
00000030  00 04 5d 2e 08 5a 29 9a  81 80 00 01 00 01 00 00  |..]..Z).........|
00000040  00 00 06 67 6f 6f 67 6c  65 03 63 6f 6d 00 00 01  |...google.com...|
00000050  00 01 c0 0c 00 01 00 01  00 00 01 2b 00 04 ac d9  |...........+....|
00000060  a0 6e                                             |.n|
00000062
```

让我们看看我们是否可以对此有所了解。从前面我们知道头是12个字节长。
对于查询数据包，标头字节为：29 9a 01 20 00 01 00 00  00 00 00 00我们可以看到最后八个字节对应于不同部分的长度，
只有一个实际具有任何内容的问题 包含一个条目的部分。
最有趣的部分是前四个字节，对应于标头的不同字段。首先，我们知道我们有一个2字节的ID，应该对查询和答案保持相同。
实际上，我们看到在此示例中，两个十六进制转储都将其设置为86 2a。
很难解析的是剩余的两个字节。为了理解它们，我们必须将它们转换为二进制。从查询数据包的01 20开始，我们发现（首先是最高有效位）
```
0 0 0 0 0 0 0 1  0 0 1 0 0 0 0 0
- -+-+-+- - - -  - -+-+- -+-+-+-
Q    O    A T R  R   Z      R
R    P    A C D  A          C
     C                      O
     O                      D
     D                      E
     E
```

Since this is a response QR is set, and so is RA to indicate that the server do support recursion. Looking at the remaining eight bytes of the reply, we see that in addition to having a single question, we've also got a single answer record.

Immediately past the header, we've got the question. Let's break it down byte by byte:
``` 
                    query name              type   class
       -----------------------------------  -----  -----
HEX    06 67 6f 6f 67 6c 65 03 63 6f 6d 00  00 01  00 01
ASCII     g  o  o  g  l  e     c  o  m
DEC    6                    3           0       1      1
```
