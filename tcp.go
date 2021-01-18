package main

import (
	"context"
	"net"
	"strconv"
	"time"
)

// 监听本地
func tcpLocal(addr string, ctx context.Context) {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return
	}
	defer l.Close()

	//循环接受连接
	for {
		select {

		case <-ctx.Done():
			return
		default:
			c, err := l.Accept()
			if err != nil {
				continue
			}
			go tcpShakehands(c)
		}
	}
}

//tcp握手
func tcpShakehands(c net.Conn) {

	defer c.Close()
	c.(*net.TCPConn).SetKeepAlive(true)

	//查找对应远程地址
	localPort := c.RemoteAddr().(*net.TCPAddr).Port

	//先找出这条连接对应的进程id 和目标信息
	pInfo, ok := tcpmap.Get(localPort)
	if ok != true {
		return
	}

	tcpmap.Del(localPort)

	//查找进程对应的代理信息
	prs, ok := proxyMap.Load(pInfo.pid)
	if !ok {
		return
	}
	pProxy, ok := prs.(ProxyInfo)
	if !ok {
		return
	}

	server := pProxy.ip + ":" + strconv.Itoa(pProxy.port)

	//连接代理
	rc, err := net.DialTimeout("tcp", server, 5*time.Second)
	if err != nil {
		return
	}
	defer rc.Close()
	rc.(*net.TCPConn).SetKeepAlive(true)

	switch pProxy.ptype {

	case AtypSocks5: //Socks5
		if err := Socks5Tcp(rc, pProxy.user, pProxy.passw, pInfo.ip); err != nil {
			return
		}

	case AtypShadowSocks: //Shadowsocks

		rc = pProxy.ciph.StreamConn(rc)
		//ss协议发送头信息
		if _, Perr := rc.Write(pInfo.ip); Perr != nil {
			return
		}

	default:
		return
	}

	//拷贝数据流 完成tcp对接
	_, _, err = relay(rc, c, pInfo.pid)
	if err != nil {
		if err, ok := err.(net.Error); ok && err.Timeout() {
			return // ignore i/o timeout
		}
	}
}

// 转发数据
func relay(left, right net.Conn, pid uint64) (int64, int64, error) {
	type res struct {
		N   int64
		Err error
	}
	ch := make(chan res)

	go func() { //recv
		n, err := Copy(right, left, AtypRecv, pid)
		right.SetDeadline(time.Now()) // wake up the other goroutine blocking on right
		left.SetDeadline(time.Now())  // wake up the other goroutine blocking on left
		ch <- res{n, err}
	}()

	//send
	n, err := Copy(left, right, AtypSend, pid)
	right.SetDeadline(time.Now()) // wake up the other goroutine blocking on right
	left.SetDeadline(time.Now())  // wake up the other goroutine blocking on left
	rs := <-ch

	if err == nil {
		err = rs.Err
	}
	return n, rs.N, err
}

func Copy(dst, src net.Conn, sc int, pid uint64) (written int64, err error) {
	buf := make([]byte, tcpBufSize)

	for {
		nr, er := src.Read(buf)
		if er != nil {
			err = er
			break
		}

		if nr > 0 {
			_, ew := dst.Write(buf[0:nr])
			if ew != nil {
				err = ew
				break
			}
		}
		//流量统计
		mcc <- mccInfo{pid: pid, to: sc, bytebyte: int64(nr)}

	}
	return written, err
}
