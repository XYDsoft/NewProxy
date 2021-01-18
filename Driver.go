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
	"strconv"
	"strings"
	"sync"
	"syscall"
	"unsafe"
)

var uMap sync.Map

//void (NFAPI_CC *threadStart)();
//export go_threadStart
func go_threadStart() {

}

//void (NFAPI_CC *threadEnd)();
//export go_threadEnd
func go_threadEnd() {

}

//void (NFAPI_CC *tcpConnectRequest)(ENDPOINT_ID id, PNF_TCP_CONN_INFO pConnInfo);
//export go_tcpConnectRequest
func go_tcpConnectRequest(id C.ENDPOINT_ID, pConnInfo C.PNF_TCP_CONN_INFO) {

	//查找进程是否需要代理
	prs, ok := proxyMap.Load(uint64(pConnInfo.processId))
	if !ok {
		return
	}
	m, ok := prs.(ProxyInfo)
	if !ok {
		return
	}

	//查询进程ID是否开启了UDP代理     1为代理 TCP   2为代理 UDP   3为 代理TCP+UDP

	if m.proxymode == 2 {
		return
	}

	//取出本地地址
	plAddr, err := (*syscall.RawSockaddrAny)(unsafe.Pointer(&(pConnInfo.localAddress))).Sockaddr()
	if err != nil {
		return
	}
	//取出远程地址
	prAddr, err := (*syscall.RawSockaddrAny)(unsafe.Pointer(&(pConnInfo.remoteAddress))).Sockaddr()
	if err != nil {
		return
	}
	//取本地端口
	var k int
	if laddrV4, ok := plAddr.(*syscall.SockaddrInet4); ok {
		k = laddrV4.Port
	} else if laddrV6, ok := plAddr.(*syscall.SockaddrInet6); ok {
		k = laddrV6.Port
	}

	var rom []byte
	if raddrV4, ok := prAddr.(*syscall.SockaddrInet4); ok {

		p := Htons(uint16(raddrV4.Port))
		ta := append([]byte{1}, raddrV4.Addr[:]...)
		rom = append(ta, p[:]...)

		tcpmap.Set(k, uint64(pConnInfo.processId), rom)

		C.setAddrV4(unsafe.Pointer(&(pConnInfo.remoteAddress)))

	} else if raddrV6, ok := prAddr.(*syscall.SockaddrInet6); ok {

		p := Htons(uint16(raddrV6.Port))
		ta := append([]byte{4}, raddrV6.Addr[:]...)
		rom = append(ta, p[:]...)

		tcpmap.Set(k, uint64(pConnInfo.processId), rom)
		C.setAddrV6(unsafe.Pointer(&(pConnInfo.remoteAddress)))
	}

}

//void (NFAPI_CC *tcpConnected)(ENDPOINT_ID id, PNF_TCP_CONN_INFO pConnInfo);
//export go_tcpConnected
func go_tcpConnected(id C.ENDPOINT_ID, pConnInfo C.PNF_TCP_CONN_INFO) {

}

//void (NFAPI_CC *tcpClosed)(ENDPOINT_ID id, PNF_TCP_CONN_INFO pConnInfo);
//export go_tcpClosed
func go_tcpClosed(id C.ENDPOINT_ID, pConnInfo C.PNF_TCP_CONN_INFO) {

}

//void (NFAPI_CC *tcpReceive)(ENDPOINT_ID id, const char * buf, int len);
//export go_tcpReceive
func go_tcpReceive(id C.ENDPOINT_ID, buf *C.char, len C.int) {

}

//void (NFAPI_CC *tcpSend)(ENDPOINT_ID id, const char * buf, int len);
//export go_tcpSend
func go_tcpSend(id C.ENDPOINT_ID, buf *C.char, len C.int) {

}

//void (NFAPI_CC *tcpCanReceive)(ENDPOINT_ID id);
//export go_tcpCanReceive
func go_tcpCanReceive(id C.ENDPOINT_ID) {

}

//void (NFAPI_CC *tcpCanSend)(ENDPOINT_ID id);
//export go_tcpCanSend
func go_tcpCanSend(id C.ENDPOINT_ID) {

}

//void (NFAPI_CC *udpCreated)(ENDPOINT_ID id, PNF_UDP_CONN_INFO pConnInfo);
//export go_udpCreated
func go_udpCreated(id C.ENDPOINT_ID, pConnInfo C.PNF_UDP_CONN_INFO) {

	//进程id
	prid := uint64(pConnInfo.processId)

	//查找进程id是否在代理列表中
	prs, ok := proxyMap.Load(prid)
	if !ok {
		return
	}
	m, ok := prs.(ProxyInfo)
	if !ok {
		return
	}

	//查询进程ID是否开启了UDP代理     1为代理 TCP   2为代理 UDP   3为 代理TCP+UDP
	if m.proxymode == 1 {
		return
	}

	uMap.Store(id, prid)

	//socks5需要tcp请求开发端口
	if m.ptype == AtypSocks5 {
		go sockHandler(id, m.ip, m.port, m.user, m.passw, m.socks)
	}

}

func sockHandler(id C.ENDPOINT_ID, ip string, port int, user string, pass string, smap *suMap) {

	//a, b, err := SocksUDPHandshake(ip, port, user, pass)
	a, b, err := Socks5Udp(ip, port, user, pass)
	if err != nil {
		return
	}

	smap.Set(int64(id), b, a)
}

//void (NFAPI_CC *udpConnectRequest)(ENDPOINT_ID id, PNF_UDP_CONN_REQUEST pConnReq);
//export go_udpConnectRequest
func go_udpConnectRequest(id C.ENDPOINT_ID, pConnReq C.PNF_UDP_CONN_REQUEST) {

}

//void (NFAPI_CC *udpClosed)(ENDPOINT_ID id, PNF_UDP_CONN_INFO pConnInfo);
//export go_udpClosed
func go_udpClosed(id C.ENDPOINT_ID, pConnInfo C.PNF_UDP_CONN_INFO) {

	//查找进程id是否在代理列表中
	prs, ok := proxyMap.Load(uint64(pConnInfo.processId))
	if !ok {
		return
	}
	m, ok := prs.(ProxyInfo)
	if !ok {
		return
	}

	//关掉socks5的握手请求
	if m.ptype == AtypSocks5 {
		m.socks.Del(int64(id))
	}

	uMap.Delete(id)
}

//void (NFAPI_CC *udpReceive)(ENDPOINT_ID id, const unsigned char * remoteAddress, const char * buf, int len, PNF_UDP_OPTIONS options);
//export go_udpReceive
func go_udpReceive(id C.ENDPOINT_ID, remoteAddress *C.uchar, buf *C.char, len C.int, options C.PNF_UDP_OPTIONS) {

	C.nf_udpPostReceive(id, remoteAddress, buf, len, options)

}

//void (NFAPI_CC *udpSend)(ENDPOINT_ID id, const unsigned char * remoteAddress, const char * buf, int len, PNF_UDP_OPTIONS options);
//export go_udpSend
func go_udpSend(id C.ENDPOINT_ID, remoteAddress *C.uchar, buf *C.char, len C.int, options C.PNF_UDP_OPTIONS) {

	//取出远程地址
	prAddr, err := (*syscall.RawSockaddrAny)(unsafe.Pointer(remoteAddress)).Sockaddr()
	if err != nil {
		return
	}

	var IP []byte
	var PORT [2]byte
	var IPTYPE int
	//取出数据包内容
	abuf := (*[1 << 30]byte)(unsafe.Pointer(buf))[:int(len)]
	var BUFF = make([]byte, int(len))
	copy(BUFF[:], abuf[:])

	if raddrV4, ok := prAddr.(*syscall.SockaddrInet4); ok {
		IPTYPE = AtypIPv4
		IP = raddrV4.Addr[:]
		PORT = Htons(uint16(raddrV4.Port))
	} else if raddrV6, ok := prAddr.(*syscall.SockaddrInet6); ok {
		IPTYPE = AtypIPv6
		IP = raddrV6.Addr[:]
		PORT = Htons(uint16(raddrV6.Port))
	} else {
		return
	}

	//DNS
	if PORT == [2]byte{0, 53} {
		if DnsAddr != nil {
			//DNS 请求
			go DNSRequest(id, remoteAddress, BUFF, options)
			return
		}

	}

	//判断id是否需要代理转发
	if pid, ok := uMap.Load(id); ok {

		if v, ook := pid.(uint64); ook {
			SendTo(id, v, IPTYPE, IP, PORT[:], BUFF, options, int(len))
		}
		return
	}

	C.nf_udpPostSend(id, remoteAddress, buf, len, options)
}

//void (NFAPI_CC *udpCanReceive)(ENDPOINT_ID id);
//export go_udpCanReceive
func go_udpCanReceive(id C.ENDPOINT_ID) {

}

//void (NFAPI_CC *udpCanSend)(ENDPOINT_ID id);
//export go_udpCanSend
func go_udpCanSend(id C.ENDPOINT_ID) {

}

//******************************************************

func DriverInit() C.int {

	return C.DriverMain()
}

func DriverFree() bool {

	C.nf_deleteRules()
	C.nf_free()

	return true
}

//********************************
func Htons(data uint16) (ret [2]byte) {
	ret[0] = byte((data >> 8) & 0xff)
	ret[1] = byte((data >> 0) & 0xff)
	return
}

func inet_addr(ipaddr string) [4]byte {
	var (
		ips = strings.Split(ipaddr, ".")
		ip  [4]uint64
		ret [4]byte
	)
	for i := 0; i < 4; i++ {
		ip[i], _ = strconv.ParseUint(ips[i], 10, 8)
	}
	for i := 0; i < 4; i++ {
		ret[i] = byte(ip[i])
	}
	return ret
}

func Int2Byte(data int) (ret []byte) {
	var len uintptr = unsafe.Sizeof(data)
	ret = make([]byte, len)
	var tmp int = 0xff
	var index uint = 0
	for index = 0; index < uint(len); index++ {
		ret[index] = byte((tmp << (index * 8) & data) >> (index * 8))
	}
	return ret
}

//构建UDP的请求包
func UDPByte(iptype int, ip []byte, port []byte, buf []byte, bufflen int, AType int) []byte {

	if iptype == AtypIPv4 {

		var buff = make([]byte, bufflen+7)

		buff[0] = AtypIPv4
		copy(buff[1:], ip[:4])
		copy(buff[5:], port[:2])
		copy(buff[7:], buf[:bufflen])

		//Socks5协议 添加额外请求头
		if AType == AtypSocks5 {
			var RetBuff = make([]byte, bufflen+7+3)
			copy(RetBuff[:2], []byte{0, 0, 0})
			copy(RetBuff[3:], buff[:bufflen+7])
			return RetBuff
		}

		return buff

	} else if iptype == AtypIPv6 {

		var buff = make([]byte, bufflen+19)

		buff[0] = AtypIPv6
		copy(buff[1:], ip[:])
		copy(buff[17:], port[:])
		copy(buff[19:], buf[:])

		//Socks5协议 添加额外请求头
		if AType == AtypSocks5 {
			var RetBuff = make([]byte, bufflen+19+3)
			copy(RetBuff[:2], []byte{0, 0, 0})
			copy(RetBuff[3:], buff[:])
			return RetBuff
		}

		return buff
	}

	return nil
}
