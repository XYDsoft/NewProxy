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
	"NewProxy/core"
	"context"
	"net"
	"strconv"
	"sync"
)

const (
	AtypIPv4        = 1
	AtypDomainName  = 3
	AtypIPv6        = 4
	AtypSend        = 0
	AtypRecv        = 1
	AtypSocks5      = 1
	AtypShadowSocks = 2
	udpBufSize      = 4096
	tcpBufSize      = 4096
)

var proxyMap sync.Map

//流量统计map
var ProcessInfo = NewProcessMap()

//tcp map
var tcpmap = NewTcpMap()

type mccInfo struct {
	pid      uint64
	to       int
	bytebyte int64 //发送量
}

type ProxyInfo struct {
	ptype     int          //代理类型 1为socks5  2为Shadowsocks
	ip        string       //代理服务器ip地址
	port      int          //代理服务器端口
	user      string       //账号
	passw     string       //密码
	ciph      core.Cipher  //ss的加密句柄
	socks     *suMap       //socks5 map
	ssAddr    *net.UDPAddr //ss的代理地址
	proxymode int          //代理控制    1为代理 TCP   2为代理 UDP   3为 代理TCP+UDP
}

//流量统计
var mcc = make(chan mccInfo, 1000)

//流量统计携程
func f(ctx context.Context) {
	for {
		select {

		case <-ctx.Done(): //退出携程
			return
		case cs := <-mcc:

			if cs.to == AtypRecv {
				ProcessInfo.Add(cs.pid, 0, cs.bytebyte)
			} else {
				ProcessInfo.Add(cs.pid, cs.bytebyte, 0)
			}
		}
	}
}

var Cancel func()

//export Driver_Init
func Driver_Init(aa *C.char, bb C.int, cc *C.char, dd *C.char) C.int { //

	tmeIp := C.GoString(aa)
	tmePort := int(bb)
	C.setPort(C.int(tmePort), cc, dd)

	var BackCtx context.Context
	BackCtx, Cancel = context.WithCancel(context.Background())

	go tcpLocal(tmeIp+":"+strconv.Itoa(tmePort), BackCtx)
	go udpLocal(tmeIp+":", BackCtx)
	go f(BackCtx)

	return DriverInit()
}

//export Driver_Free
func Driver_Free() bool {

	if Cancel != nil {
		Cancel()
	}

	return DriverFree()
}

//export GetInfo
func GetInfo(pid C.ulong, c C.int) C.longlong { //1=send  0=recv

	mm := ProcessInfo.Get(uint64(pid))
	if int(c) == 1 {
		return C.longlong(mm.send)

	}
	return C.longlong(mm.recv)
}

//export AddProxy
func AddProxy(a1 C.int, a2 C.ulong, a3 *C.char, a4 C.int, a5 *C.char, a6 *C.char, a7 C.int) bool {
	ptype := int(a1)
	pid := uint64(a2)
	ip := C.GoString(a3)
	port := int(a4)
	user := C.GoString(a5)
	pass := C.GoString(a6)
	modes := int(a7)

	//进程id存在
	if _, ok := proxyMap.Load(pid); ok {
		return false
	}

	switch ptype {

	case AtypSocks5:

		p := ProxyInfo{
			ptype:     AtypSocks5,
			ip:        ip,
			port:      port,
			user:      user,
			passw:     pass,
			ciph:      nil,
			socks:     NewSuMap(),
			ssAddr:    nil,
			proxymode: modes,
		}

		proxyMap.Store(pid, p)
		return true

	case AtypShadowSocks:

		var key []byte
		ciph, err := core.PickCipher(user, key, pass)
		if err != nil {
			return false
		}

		mAddr, err := net.ResolveUDPAddr("udp", ip+":"+strconv.Itoa(port))
		if err != nil {
			return false
		}
		p := ProxyInfo{
			ptype:     AtypShadowSocks,
			ip:        ip,
			port:      port,
			user:      user,
			passw:     pass,
			ciph:      ciph,
			socks:     nil,
			ssAddr:    mAddr,
			proxymode: modes,
		}

		proxyMap.Store(pid, p)

		return true
	default:
		return false
	}
	return false
}

//export DelteProxy
func DelteProxy(pid C.ulong) bool {

	id := uint64(pid)

	//查找进程对应的代理信息
	prs, ok := proxyMap.Load(id)
	if !ok {
		return false
	}
	pProxy, ok := prs.(ProxyInfo)
	if !ok {
		return false
	}
	//关闭socks5握手
	if pProxy.ptype == AtypSocks5 {
		go pProxy.socks.DelAll()

	}

	//删除代理信息
	proxyMap.Delete(id)
	//删除流量统计
	ProcessInfo.Del(id)
	return true

}

var DnsAddr *net.UDPAddr //dns 地址
var DnsOut int           //dns超时时间

var DnsPacket core.Cipher //dns代理加密方式
var DnsPAddr *net.UDPAddr //dns代理服务器

//export SetDns
func SetDns(a1 *C.char, a2 C.int, a3 C.int) bool {

	return false

	sAddr := C.GoString(a1)
	sPort := int(a2)
	out := int(a3)

	if sAddr == "" {
		DnsAddr = nil
		return true
	}

	var err error
	DnsOut = out
	DnsAddr, err = net.ResolveUDPAddr("udp", sAddr+":"+strconv.Itoa(sPort))
	if err != nil {
		return false
	}
	return true
}

//export SetDnsProxy
func SetDnsProxy(a1 *C.char, a2 C.int, a3 *C.char, a4 *C.char) bool {

	return false

	sAddr := C.GoString(a1)
	sPort := int(a2)
	user := C.GoString(a3)
	pass := C.GoString(a4)

	if sAddr == "" {
		DnsPAddr = nil
		return true
	}

	var key []byte
	var err error
	DnsPacket, err = core.PickCipher(user, key, pass)
	if err != nil {
		return false
	}

	DnsPAddr, err = net.ResolveUDPAddr("udp", sAddr+":"+strconv.Itoa(sPort))
	if err != nil {
		return false
	}

	return true

}

func main() {
	// Need a main function to make CGO compile package as C shared library

}
