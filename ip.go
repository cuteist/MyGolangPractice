package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"strings"
	"time"
)

func main() {
	for _, IPver := range []int{4, 6} {
		publicIP, err := getPublicIP(IPver)
		if err != nil {
			fmt.Printf("%s", err)
		}
		fmt.Println(publicIP)
	}
}

func getPublicIP(IPver int) (string, error) {
	stunServer := "stun.cloudflare.com:3478"
	if IPver != 4 && IPver != 6 {
		return "", fmt.Errorf("invalid IP version %d, excepted 4 or 6\n", IPver)
	}

	rand.Seed(time.Now().UnixNano())
	conn, err := net.Dial(fmt.Sprintf("udp%d", IPver), stunServer)
	if err != nil {
		if strings.HasSuffix(err.Error(), "unreachable") {
			return "", fmt.Errorf("no IPv%d", IPver)
		}
		return "", err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))

	// STUN message header
	var messageType uint16 = 0x0001 // Binding Request
	var messageLength uint16 = 0x0000
	var magicCookie uint32 = 0x2112A442

	transactionID := make([]byte, 12)
	rand.Read(transactionID)

	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, messageType)
	binary.Write(buf, binary.BigEndian, messageLength)
	binary.Write(buf, binary.BigEndian, magicCookie)
	buf.Write(transactionID)

	_, err = conn.Write(buf.Bytes())
	if err != nil {
		return "", err
	}

	reply := make([]byte, 1024)
	_, err = conn.Read(reply)
	if err != nil {
		return "", err
	}

	// Parse STUN message
	if !bytes.Equal(reply[4:8], buf.Bytes()[4:8]) {
		return "", fmt.Errorf("invalid magic cookie in response")
	}
	if !bytes.Equal(reply[8:20], buf.Bytes()[8:20]) {
		return "", fmt.Errorf("transaction ID mismatch in response")
	}

	// Parse STUN attributes
	attributes := reply[20:]
	for len(attributes) > 0 {
		attrType := binary.BigEndian.Uint16(attributes[:2])
		attrLength := binary.BigEndian.Uint16(attributes[2:4])
		if attrLength < 8 {
			return "", fmt.Errorf("invalid address attribute length")
		}
		if len(attributes) < 4+int(attrLength) { //TODO: more precise
			return "", fmt.Errorf("invalid attribute length")
		}

		attributeValue := attributes[4 : 4+attrLength]
		family := attributeValue[1]

		if attrType == 0x0001 { // Mapped Address
			// port := binary.BigEndian.Uint16(attributeValue[2:4])
			//TODO: reduce code
			switch family {
			case 1:
				ip := net.IP(attributeValue[4:8])
				return ip.String(), nil
			case 2:
				ip := net.IP(attributeValue[4:20])
				return ip.String(), nil
			default:
				return "", fmt.Errorf("unknown address family")
			}
		} else if attrType == 0x0020 { // XOR-Mapped Address
			// port := binary.BigEndian.Uint16(attributeValue[2:4])
			var ip []byte
			switch family {
			case 1:
				ip = attributeValue[4:8]
			case 2:
				ip = attributeValue[4:20]
				for i := 4; i < len(ip); i++ {
					ip[i] ^= transactionID[i-4]
				}
			default:
				return "", fmt.Errorf("unknown address family")
			}

			magicCookieBytes := make([]byte, 4)
			binary.BigEndian.PutUint32(magicCookieBytes, magicCookie)
			for i := 0; i < 4; i++ {
				ip[i] ^= magicCookieBytes[i]
			}

			return net.IP(ip).String(), nil
		}
	}

	return "", fmt.Errorf("public IP not found in STUN response")
}
