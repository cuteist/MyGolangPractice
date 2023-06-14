package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
)

var (
	socksAddress  = flag.String("address", "", "Listening address")
	socksPort     = flag.Int("port", 1080, "Listening port")
	socksUsername = flag.String("username", "", "Socks username")
	socksPassword = flag.String("password", "", "Socks password")
	enableLog     = flag.Bool("log", false, "Enable log")
)

var needAuth = false

func main() {
	flag.Parse()
	needAuth = *socksUsername != "" && *socksPassword != ""
	socksServer := fmt.Sprintf("%s:%d", *socksAddress, *socksPort)
	server, err := net.Listen("tcp", socksServer)
	if *socksAddress == "" {
		fmt.Printf("Socks server listening *:%d\n", *socksPort)
	} else {
		fmt.Printf("Socks server listening %s\n", socksServer)
	}
	if needAuth {
		fmt.Printf("Username: %s\nPassword: %s\n", *socksUsername, *socksPassword)
	}

	if err != nil {
		fmt.Printf("Listen failed: %v\n", err)
		return
	}

	for {
		client, err := server.Accept()
		if err != nil {
			fmt.Printf("Accept failed: %v", err)
			continue
		}
		if *enableLog {
			fmt.Printf("Client:   %s\n", client.RemoteAddr())
		}
		go process(client)
	}
}

func process(client net.Conn) {
	if err := Socks5Auth(client); err != nil {
		fmt.Println("auth error:", err)
		client.Close()
		return
	}

	target, err := Socks5Connect(client)
	if err != nil {
		fmt.Println("connect error:", err)
		client.Close()
		return
	}

	Socks5Relay(client, target)
}

func Socks5Auth(client net.Conn) (err error) {
	buf := make([]byte, 256)

	n, err := io.ReadFull(client, buf[:2])
	if n != 2 {
		return errors.New("read header: " + err.Error())
	}

	ver, nMethods := int(buf[0]), int(buf[1])
	if ver != 5 {
		return errors.New("invalid version")
	}

	n, err = io.ReadFull(client, buf[:nMethods])
	if n != nMethods {
		return errors.New("read methods: " + err.Error())
	}

	if needAuth {
		n, err = client.Write([]byte{0x05, 0x02})
		if n != 2 || err != nil {
			return errors.New("write response: " + err.Error())
		}
		n, err = io.ReadFull(client, buf[:2])
		if n != 2 {
			return errors.New("read auth request: " + err.Error())
		}
		ver = int(buf[0])
		if ver != 1 {
			return errors.New("invalid auth version")
		}

		ulen := int(buf[1])
		n, err = io.ReadFull(client, buf[:ulen])
		if n != ulen {
			return errors.New("read username: " + err.Error())
		}
		username := string(buf[:ulen])

		n, err = io.ReadFull(client, buf[:1])
		if n != 1 {
			return errors.New("read password: " + err.Error())
		}
		plen := int(buf[0])
		n, err = io.ReadFull(client, buf[:plen])
		if n != plen {
			return errors.New("read password: " + err.Error())
		}
		password := string(buf[:plen])

		if username != *socksUsername || password != *socksPassword {
			return errors.New("invalid username/password: " + username + "/" + password)
		}
		n, err = client.Write([]byte{0x01, 0x00})
		if n != 2 || err != nil {
			return errors.New("write response: " + err.Error())
		}
	} else {
		n, err = client.Write([]byte{0x05, 0x00})
		if n != 2 || err != nil {
			return errors.New("write response: " + err.Error())
		}
	}
	return nil
}

func Socks5Connect(client net.Conn) (net.Conn, error) {
	buf := make([]byte, 256)

	n, err := io.ReadFull(client, buf[:4])
	if n != 4 {
		return nil, errors.New("read header: " + err.Error())
	}

	ver, cmd, _, addrType := buf[0], buf[1], buf[2], buf[3]
	if ver != 5 {
		return nil, errors.New("invalid version")
	}
	if cmd != 1 && cmd != 3 {
		return nil, errors.New("invalid cmd:" + string('0'+cmd))
	}

	//todo udp associate
	if cmd == 3 {
	}

	addr := ""
	switch addrType {
	case 1:
		n, err = io.ReadFull(client, buf[:4])
		if n != 4 {
			return nil, errors.New("invalid IPv4: " + err.Error())
		}
		addr = net.IP(buf[:4]).String()
	case 3:
		n, err = io.ReadFull(client, buf[:1])
		if n != 1 {
			return nil, errors.New("invalid hostname: " + err.Error())
		}
		addrLen := int(buf[0])

		n, err = io.ReadFull(client, buf[:addrLen])
		if n != addrLen {
			return nil, errors.New("invalid hostname: " + err.Error())
		}
		addr = string(buf[:addrLen])
	case 4:
		n, err = io.ReadFull(client, buf[:16])
		if n != 16 {
			return nil, errors.New("invalid IPv6: " + err.Error())
		}
		addr = fmt.Sprintf("[%s]", net.IP(buf[:16]).String())
	default:
		return nil, errors.New("invalid addressType")
	}

	n, err = io.ReadFull(client, buf[:2])
	if n != 2 {
		return nil, errors.New("read port: " + err.Error())
	}

	port := uint(buf[0])<<8 + uint(buf[1])
	destAddrPort := fmt.Sprintf("%s:%d", addr, port)
	if *enableLog {
		fmt.Println("Connect: ", destAddrPort)
	}
	dest, err := net.Dial("tcp", destAddrPort)
	if err != nil {
		return nil, errors.New("dial destination: " + err.Error())
	}

	n, err = client.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	if err != nil {
		dest.Close()
		return nil, errors.New("write response: " + err.Error())
	}

	return dest, nil
}

func Socks5Relay(client, target net.Conn) {
	relay := func(source, destination net.Conn) {
		defer source.Close()
		defer destination.Close()
		io.Copy(source, destination)
	}
	go relay(client, target)
	go relay(target, client)
}
