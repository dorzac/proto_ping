# proto_ping
proto_ping is a recreation of the Unix `Ping` program written in Rust.
It concurrently sends and receives echo request packets from a requested IP Address.
It handles both IPv4 and IPv6.

```
proto_ping 0.1.0
dorzac <dorzac0@gmail.com>

USAGE:
    proto_ping [OPTIONS] <tgt_ip> [Binary]
    cargo run [OPTIONS] <tgt_ip> [from source]
FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -t, --ttl <ttl>     [default: 100]

ARGS:
    <tgt_ip>        IP address
```

### Troubleshooting
It's possible that on some OSs, opening a transport channel gets blocked. Try with `sudo`
