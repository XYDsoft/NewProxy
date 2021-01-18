package main

/*
#cgo  CFLAGS:  -I  ./include
#cgo  LDFLAGS:  -L ./lib  -lnfapi

#include <stdio.h>
#include <stdlib.h>
#include "nfapi.h"
*/
import "C"

import (
	"context"
	"fmt"
	"net"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

type tmebuf struct {
	id      C.ENDPOINT_ID
	pid     uint64
	iptype  int
	ip      []byte
	port    []byte
	buf     []byte
	options C.PNF_UDP_OPTIONS
	len     int
}

var ch = make(chan tmebuf, 5000)

//发送函数
func SendTo(id C.ENDPOINT_ID, pid uint64, iptype int, ip []byte, port []byte, buf []byte, opt C.PNF_UDP_OPTIONS, l int) {

	ch <- tmebuf{id: id, pid: pid, iptype: iptype, ip: ip, port: port, buf: buf, options: opt, len: l}

}

// Udp 本地监听转发
func udpLocal(localaddr string, ctx context.Context) {

	//udp超时
	var nm = newNATmap(5 * time.Minute)
	var pBuf tmebuf

	for {

		select {
		case <-ctx.Done(): //关闭信号
			return

		case pBuf = <-ch: //数据处理

			//查找进程对应的代理信息
			prs, ok := proxyMap.Load(pBuf.pid)
			if !ok {
				continue
			}
			ProcessProxy, ok := prs.(ProxyInfo)
			if !ok {
				continue
			}

			key := string(pBuf.id)

			switch ProcessProxy.ptype {

			case AtypSocks5: //Socks5

				//查找驱动ID对应的Socks5握手端口
				Socks, ok := ProcessProxy.socks.Get(int64(pBuf.id))
				if ok != true {
					continue
				}

				//Socks5的发送地址为空则丢弃该包
				if Socks.server == nil {
					continue
				}

				//在UDP NAT 中查找记录
				pc := nm.Get(key)

				if pc == nil {
					var err error
					pc, err = net.ListenPacket("udp", localaddr)
					if err != nil {
						continue
					}
					//NAT 添加记录
					nm.Add(key, tmebuf{id: pBuf.id, pid: pBuf.pid, options: pBuf.options}, pc, AtypSocks5, ProcessProxy.socks)
				}

				//发送UDP请求
				buf := UDPByte(pBuf.iptype, pBuf.ip, pBuf.port, pBuf.buf, pBuf.len, AtypSocks5)
				if buf == nil {
					continue
				}
				n, err := pc.WriteTo(buf, Socks.server)
				if err != nil {
					continue
				}

				mcc <- mccInfo{pid: pBuf.pid, to: AtypSend, bytebyte: int64(n)}

			case AtypShadowSocks: //Shadowsocks

				pc := nm.Get(key)
				if pc == nil {
					var err error
					pc, err = net.ListenPacket("udp", localaddr)
					if err != nil {
						continue
					}
					pc = ProcessProxy.ciph.PacketConn(pc)
					//NAT 添加记录
					nm.Add(key, tmebuf{id: pBuf.id, options: pBuf.options, pid: pBuf.pid}, pc, AtypShadowSocks, nil)
				}

				//发送UDP请求
				buf := UDPByte(pBuf.iptype, pBuf.ip, pBuf.port, pBuf.buf, pBuf.len, AtypShadowSocks)
				if buf == nil {
					continue
				}

				n, err := pc.WriteTo(buf, ProcessProxy.ssAddr)
				if err != nil {
					continue
				}
				mcc <- mccInfo{pid: pBuf.pid, to: AtypSend, bytebyte: int64(n)}

			default:
				continue
			}
		}

	}
}

// Packet NAT table
type natmap struct {
	sync.RWMutex
	m       map[string]net.PacketConn
	timeout time.Duration
}

func newNATmap(timeout time.Duration) *natmap {
	m := &natmap{}
	m.m = make(map[string]net.PacketConn)
	m.timeout = timeout
	return m
}

func (m *natmap) Get(key string) net.PacketConn {
	m.RLock()
	defer m.RUnlock()
	return m.m[key]
}

func (m *natmap) Set(key string, pc net.PacketConn) {
	m.Lock()
	defer m.Unlock()

	m.m[key] = pc
}

func (m *natmap) Del(key string) {
	m.Lock()
	defer m.Unlock()

	if pc, ok := m.m[key]; ok {
		pc.Close()
		delete(m.m, key)
	}
}

func (m *natmap) Add(peer string, dst tmebuf, src net.PacketConn, info int, suP *suMap) {
	m.Set(peer, src)

	go func() {
		//Copy 把代理返回的数据拷贝到驱动上
		timedCopy(dst, src, m.timeout, info)

		m.Del(peer)
		//关闭socks5 握手连接
		if suP != nil {
			suP.Del(int64(dst.id))
		}
	}()

}

// 使用读取超时将src复制到目标上的dst
func timedCopy(dst tmebuf, src net.PacketConn, timeout time.Duration, info int) error {
	buf := make([]byte, udpBufSize)

	switch info {

	case AtypSocks5: //Socks5
		for {
			src.SetReadDeadline(time.Now().Add(timeout))
			n, _, err := src.ReadFrom(buf)
			if err != nil {
				return err
			}

			if buf[3] == AtypIPv4 {

				var temaddr syscall.SockaddrInet4
				C.memcpy(unsafe.Pointer(&temaddr.Addr), unsafe.Pointer(&buf[4]), 4)
				p := [2]byte{buf[1+net.IPv4len+3], buf[1+net.IPv4len+1+3]}
				C.memcpy(unsafe.Pointer(&temaddr.Port), unsafe.Pointer(&p[0]), 4)

				C.nf_udpPostReceive(dst.id, (*C.uchar)(unsafe.Pointer(&temaddr)), (*C.char)(unsafe.Pointer(&buf[10])), C.int(n-10), dst.options)
				mcc <- mccInfo{pid: dst.pid, to: AtypRecv, bytebyte: int64(n)}
				continue

			} else {

				var temaddr syscall.SockaddrInet6
				C.memcpy(unsafe.Pointer(&temaddr.Addr), unsafe.Pointer(&buf[4]), 16)
				p := [2]byte{buf[1+net.IPv6len+3], buf[1+net.IPv6len+1+3]}
				C.memcpy(unsafe.Pointer(&temaddr.Port), unsafe.Pointer(&p[0]), 4)

				C.nf_udpPostReceive(dst.id, (*C.uchar)(unsafe.Pointer(&temaddr)), (*C.char)(unsafe.Pointer(&buf[22])), C.int(n-22), dst.options)
				mcc <- mccInfo{pid: dst.pid, to: AtypRecv, bytebyte: int64(n)}
				continue

			}
		}

	case AtypShadowSocks: //Shadowsocks
		for {
			src.SetReadDeadline(time.Now().Add(timeout))
			n, _, err := src.ReadFrom(buf)
			if err != nil {
				return err
			}

			if buf[0] == AtypIPv4 {

				var temaddr syscall.SockaddrInet4
				C.memcpy(unsafe.Pointer(&temaddr.Addr), unsafe.Pointer(&buf[1]), 4)
				p := [2]byte{buf[1+net.IPv4len], buf[1+net.IPv4len+1]}
				C.memcpy(unsafe.Pointer(&temaddr.Port), unsafe.Pointer(&p[0]), 4)

				C.nf_udpPostReceive(dst.id, (*C.uchar)(unsafe.Pointer(&temaddr)), (*C.char)(unsafe.Pointer(&buf[7])), C.int(n-7), dst.options)
				mcc <- mccInfo{pid: dst.pid, to: AtypRecv, bytebyte: int64(n)}
				continue

			} else {

				var temaddr syscall.SockaddrInet6
				C.memcpy(unsafe.Pointer(&temaddr.Addr), unsafe.Pointer(&buf[1]), 16)
				p := [2]byte{buf[1+net.IPv6len], buf[1+net.IPv6len+1]}
				C.memcpy(unsafe.Pointer(&temaddr.Port), unsafe.Pointer(&p[0]), 4)

				C.nf_udpPostReceive(dst.id, (*C.uchar)(unsafe.Pointer(&temaddr)), (*C.char)(unsafe.Pointer(&buf[19])), C.int(n-19), dst.options)
				mcc <- mccInfo{pid: dst.pid, to: AtypRecv, bytebyte: int64(n)}
				continue

			}
		}

	default:
		return fmt.Errorf("err")
	}

}
