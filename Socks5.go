package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"
)

func SocksHandle(conn net.Conn, ip []byte) (err error) {

	buf := append([]byte{5, 1, 0}, ip...)
	conn.SetWriteDeadline(time.Now().Add(time.Second))
	_, err = conn.Write(buf[:])
	if err != nil {
		return
	}
	var resp [2]byte

	conn.SetReadDeadline(time.Now().Add(time.Second))
	r := bufio.NewReader(conn)
	_, err = io.ReadFull(r, resp[:2])

	if err != nil {
		return
	}

	if resp[1] != 0x00 {

		return fmt.Errorf("err", err)
	}
	conn.SetDeadline(time.Time{})

	return
}

func Socks5Tcp(conn net.Conn, user, pass string, ip []byte) (err error) {

	conn.SetWriteDeadline(time.Now().Add(time.Second))
	var req [4]byte
	req[0] = 5
	req[1] = 2
	req[2] = 0
	req[3] = 2
	_, err = conn.Write(req[:])
	if err != nil {
		return
	}

	conn.SetReadDeadline(time.Now().Add(time.Second))
	// 接收服务器应答
	var resp [2]byte
	r := bufio.NewReader(conn)
	_, err = io.ReadFull(r, resp[:2])

	if err != nil {
		return
	}
	// 不需要密码 验证通过
	if resp[1] == 0x00 {

		return SocksHandle(conn, ip)
	}

	// 构建用户名密码数据包
	b := make([]byte, 513)
	b[0] = 0x01
	uLen := len(user)
	b[1] = byte(uLen)
	idx := 2 + uLen
	copy(b[2:idx], user)

	pLen := len(pass)
	b[idx] = byte(pLen)
	idx++
	copy(b[idx:idx+pLen], pass)
	idx += pLen
	conn.SetWriteDeadline(time.Now().Add(time.Second))
	if _, err = conn.Write(b[:idx]); err != nil {
		return
	}

	// 设置接收数据超时
	conn.SetReadDeadline(time.Now().Add(time.Second))
	// 接收服务器应答
	r = bufio.NewReader(conn)

	if _, err = io.ReadFull(r, resp[:2]); err != nil {
		return
	}
	// 服务器校验认证错误
	if resp[0] != 0x01 {
		return fmt.Errorf("err", err)
	}

	return SocksHandle(conn, ip)
}

func Socks5Udp(ip string, port int, user, pass string) (addr net.Addr, c net.Conn, err error) {

	server := ip + ":" + strconv.Itoa(port)

	conn, err := net.Dial("tcp", server)
	if err != nil {
		return
	}

	conn.SetWriteDeadline(time.Now().Add(time.Second))
	var req [4]byte
	req[0] = 5
	req[1] = 2
	req[2] = 0
	req[3] = 2
	_, err = conn.Write(req[:])
	if err != nil {
		return
	}

	conn.SetReadDeadline(time.Now().Add(time.Second))
	// 接收服务器应答
	var resp [2]byte
	r := bufio.NewReader(conn)
	_, err = io.ReadFull(r, resp[:2])
	if err != nil {
		return
	}

	// 不需要密码 验证通过
	if resp[1] == 0x00 {
		return Udphandle(conn, ip)
	}

	// 构建用户名密码数据包
	b := make([]byte, 513)
	b[0] = 0x01
	uLen := len(user)
	b[1] = byte(uLen)
	idx := 2 + uLen
	copy(b[2:idx], user)

	pLen := len(pass)
	b[idx] = byte(pLen)
	idx++
	copy(b[idx:idx+pLen], pass)
	idx += pLen
	conn.SetWriteDeadline(time.Now().Add(time.Second))
	if _, err = conn.Write(b[:idx]); err != nil {
		return
	}

	// 设置接收数据超时
	conn.SetReadDeadline(time.Now().Add(time.Second))
	// 接收服务器应答
	r = bufio.NewReader(conn)

	if _, err = io.ReadFull(r, resp[:2]); err != nil {
		return
	}
	// 服务器校验认证错误
	if resp[1] != 0x00 {
		err = fmt.Errorf("err")
		return

	}

	return Udphandle(conn, ip)

}

func Udphandle(conn net.Conn, ip string) (addr net.Addr, c net.Conn, err error) {

	buf := []byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0}
	conn.SetWriteDeadline(time.Now().Add(time.Second))
	_, err = conn.Write(buf[:])
	if err != nil {
		return
	}
	var resp [10]byte
	conn.SetReadDeadline(time.Now().Add(time.Second))
	r := bufio.NewReader(conn)
	_, err = io.ReadFull(r, resp[:10])
	if err != nil {
		return
	}

	if resp[1] != 0x00 {

		return nil, nil, fmt.Errorf("err", err)
	}
	//{5,0,0,1,172,16,0,5,207,171}

	m := strconv.Itoa((int(resp[8]) << 8) | int(resp[9]))
	srvAddr, err := net.ResolveUDPAddr("udp", ip+":"+m)
	if err != nil {
		return
	}

	conn.SetDeadline(time.Time{})
	return srvAddr, conn, nil

}
