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
	if IPver != 4 && IPver != 6 {
		return "", fmt.Errorf("invalid IP version %d, excepted 4 or 6\n", IPver)
	}

	stunServer := "stun.cloudflare.com:3478"

	rand.Seed(time.Now().UnixNano())
	conn, err := net.Dial(fmt.Sprintf("udp%d", IPver), stunServer)
	if err != nil {
		if strings.HasSuffix(err.Error(), "network is unreachable") {
			return "", fmt.Errorf("no IPv%d", IPver)
		}
		if strings.HasSuffix(err.Error(), "no suitable address found") {
			return "", fmt.Errorf("the STUN server doesn't support IPv%d", IPver)
		}
		return "", err
	}

	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))

	// https://www.rfc-editor.org/rfc/rfc5389.html#section-6
	// STUN Message Structure
	// 	0                   1                   2                   3
	// 	0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |0 0|     STUN Message Type     |         Message Length        |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |                         Magic Cookie                          |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |                                                               |
	// |                     Transaction ID (96 bits)                  |
	// |                                                               |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

	// STUN message header
	buf := new(bytes.Buffer)
	// Start with fixed 0x00, message type: 0x01, message length: 0x0000
	buf.Write([]byte{0x00, 0x01, 0x00, 0x00})
	magicCookie := []byte{0x21, 0x12, 0xA4, 0x42}
	buf.Write(magicCookie)
	transactionID := make([]byte, 12)
	rand.Read(transactionID)
	buf.Write(transactionID)

	_, err = conn.Write(buf.Bytes())
	if err != nil {
		return "", err
	}

	response := make([]byte, 1024)
	n, err := conn.Read(response)
	if err != nil {
		return "", err
	}
	if n < 32 {
		return "", fmt.Errorf("invalid response")
	}

	// Parse STUN message
	if !bytes.Equal(response[4:8], buf.Bytes()[4:8]) {
		return "", fmt.Errorf("invalid magic cookie in response")
	}
	if !bytes.Equal(response[8:20], buf.Bytes()[8:20]) {
		return "", fmt.Errorf("transaction ID mismatch in response")
	}

	// https://www.rfc-editor.org/rfc/rfc5389.html#section-15
	// STUN Attributes
	// 	0                   1                   2                   3
	// 	0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |         Type                  |            Length             |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |                         Value (variable)                ....
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

	// Parse STUN attributes
	attributes := response[20:]

	attrType := binary.BigEndian.Uint16(attributes[:2])
	// Mapped Address && Xor-Mapped Address
	if attrType != 0x0001 && attrType != 0x0020 {
		return "", fmt.Errorf("invalid address attribute type")
	}
	attrLength := binary.BigEndian.Uint16(attributes[2:4])
	if attrLength < 8 {
		return "", fmt.Errorf("invalid address attribute length")
	}

	// https://www.rfc-editor.org/rfc/rfc5389.html#section-15.1
	// MAPPED-ADDRESS
	//  0                   1                   2                   3
	// 	0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |0 0 0 0 0 0 0 0|    Family     |           Port                |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |                                                               |
	// |                 Address (32 bits or 128 bits)                 |
	// |                                                               |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// https://www.rfc-editor.org/rfc/rfc5389.html#section-15.2
	// XOR-MAPPED-ADDRESS
	//  0                   1                   2                   3
	//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |x x x x x x x x|    Family     |         X-Port                |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |                X-Address (Variable)
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	attributeValue := attributes[4 : 4+attrLength]
	family := attributeValue[1]
	var ip []byte
	switch family {
	case 1:
		ip = attributeValue[4:8]
	case 2:
		ip = attributeValue[4:20]
	default:
		return "", fmt.Errorf("unknown address family")
	}
	if attrType == 0x0020 { // XOR-Mapped Address
		for i := 0; i < 4; i++ {
			ip[i] ^= magicCookie[i]
		}
		if family == 2 {
			for i := 4; i < len(ip); i++ {
				ip[i] ^= transactionID[i-4]
			}
		}
	}
	return net.IP(ip).String(), nil
}
