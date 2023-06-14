### socks5_server.go
A simple SOCKS5 server
```bash
go build socks5_server.go
./socks5_server -h
```

help information:
```
Usage of ./socks5_server:
  -address string
        Listening address
  -log
        Enable log
  -password string
        Socks password
  -port int
        Listening port (default 1080)
  -username string
        Socks username
```

Example:
```bash
./socks5_server -address 127.0.0.1 -username user -passname pass -log true
```

### gip.go

**g**et public **ip** (IPv4 and IPv6) from STUN server(default: stun.cloudflare.com:3478)  
A simple STUN protocol application, no third-party package dependency

```bash
go build gip.go
./gip
```