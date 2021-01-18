package main

/*
#cgo  LDFLAGS: -lwsock32
#cgo  LDFLAGS: -lWs2_32
#cgo  CFLAGS:  -I  ./include
#cgo  LDFLAGS:  -L ./lib  -lnfapi

#include <stdio.h>
#include <stdlib.h>
#include "nfapi.h"
#include "Driver.h"
*/
import "C"

import (
	"fmt"
	"net"
	"time"
	"unsafe"
)

func DNSRequest(id C.ENDPOINT_ID, remoteAddress *C.uchar, buf []byte, options C.PNF_UDP_OPTIONS) {

	conn, err := net.ListenPacket("udp", "")
	if err != nil {
		return
	}
	defer conn.Close()

	if DnsPAddr != nil {
		conn = DnsPacket.PacketConn(conn)
		//给数据加包头

		hostType, host, port, err := NetAddrToSocksAddr(DnsAddr)
		if err != nil {
			return
		}

		var buff = []byte{hostType}
		buff = append(buff, host[:]...)
		buff = append(buff, port[:]...)
		buff = append(buff, buf[:]...)

		_, err = conn.WriteTo(buff[:], DnsPAddr)
		if err != nil {
			return
		}

	} else {
		_, err = conn.WriteTo(buf[:], DnsAddr)
		if err != nil {
			return
		}
	}

	rbuf := make([]byte, 1024)
	conn.SetReadDeadline(time.Now().Add(time.Millisecond * time.Duration(DnsOut)))
	n, _, err := conn.ReadFrom(rbuf)
	if err != nil {
		return
	}

	//ss 去掉协议头
	if DnsPAddr != nil {

		var ssbuf []byte
		if rbuf[0] == AtypIPv4 {
			ssbuf = rbuf[7:n]
		} else {
			ssbuf = rbuf[19:n]
		}

		C.nf_udpPostReceive(id, remoteAddress, (*C.char)(unsafe.Pointer(&ssbuf[0])), C.int(len(ssbuf)), options)
		return
	}

	C.nf_udpPostReceive(id, remoteAddress, (*C.char)(unsafe.Pointer(&rbuf[0])), C.int(n), options)
}

func NetAddrToSocksAddr(addr interface{}) (hostType byte, host []byte, port [2]byte, err error) {

	switch addr.(type) {
	case *net.UDPAddr:
		a := addr.(*net.UDPAddr)
		hostType = AtypIPv4
		host = a.IP.To4()
		port = Htons(uint16(a.Port))
	case *net.TCPAddr:
		a := addr.(*net.TCPAddr)
		hostType = AtypIPv4
		host = a.IP.To4()
		port = Htons(uint16(a.Port))
	default:
		err = fmt.Errorf("err")
	}

	return
}
