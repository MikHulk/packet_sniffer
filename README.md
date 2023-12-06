A little packet sniffer written with Rust, based on [libpnet](https://github.com/libpnet/libpnet).

You can run the application with cargo:

```
 % cargo run -- --help
    Finished dev [unoptimized + debuginfo] target(s) in 0.02s
     Running `target/debug/packet_sniffer --help`
packet_sniffer 0.1.0
Mickaël Viey. <m.viey@wanadoo.fr>
A light packet sniffer

USAGE:
    packet_sniffer [OPTIONS] <IFACE>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -d, --ipdst <IPDST>...      keep packets going towards this ip
    -s, --ipsrc <IPSRC>...      keep packets originated from this ip
    -t, --ethtype <PROTO>       keep ethernet frame with this type.
    -p, --srcport <PTSRC>...    keep packets originated from this port

ARGS:
    <IFACE>    Interface to sniff
```


Don't forget you need root access to read from interfaces:

```
% sudo cargo run -- en0
    Finished dev [unoptimized + debuginfo] target(s) in 0.02s
     Running `target/debug/packet_sniffer en0`
Udp: 192.168.1.7 -> 255.255.255.255, 100 bytes
	flags: DON'T FRAGMENT(000)
TCP seq: 648117857, 46.16.175.175:6697 -> 192.168.1.7:59279, 145 bytes
	IP flags: DON'T FRAGMENT(010)
	TCP flags: ACK, PSH(000011000)
TCP seq: 2148319389, 192.168.1.7:59279 -> 46.16.175.175:6697, 52 bytes
	IP flags: DON'T FRAGMENT(010)
	TCP flags: ACK(000010000)
TCP seq: 648117950, 46.16.175.175:6697 -> 192.168.1.7:59279, 147 bytes
	IP flags: DON'T FRAGMENT(010)
	TCP flags: ACK, PSH(000011000)
TCP seq: 2148319389, 192.168.1.7:59279 -> 46.16.175.175:6697, 52 bytes
	IP flags: DON'T FRAGMENT(010)
	TCP flags: ACK(000010000)
TCP seq: 648118045, 46.16.175.175:6697 -> 192.168.1.7:59279, 176 bytes
	IP flags: DON'T FRAGMENT(010)
	TCP flags: ACK, PSH(000011000)
TCP seq: 2148319389, 192.168.1.7:59279 -> 46.16.175.175:6697, 52 bytes
	IP flags: DON'T FRAGMENT(010)
	TCP flags: ACK(000010000)
Udp: 192.168.1.7 -> 255.255.255.255, 100 bytes
	flags: DON'T FRAGMENT(000)
...
```
