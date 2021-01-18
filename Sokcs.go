package main

import (
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/FlowerWrong/gosocks"
)

func SocksUDPHandshake(ip string, port int, user, pass string) (net.Addr, net.Conn, error) {

	b := gosocks.SocksDialer{
		Timeout:    time.Second * 5,
		Auth:       &gosocks.AnonymousClientAuthenticator{},
		ControlFun: nil,
	}

	rDr := "postgres://" + user + ":" + pass + "@" + ip + ":" + strconv.Itoa(port)

	socks5TcpConn, err := b.Dial(rDr)
	if err != nil {
		return nil, nil, err
	}

	_, err = gosocks.WriteSocksRequest(socks5TcpConn, &gosocks.SocksRequest{
		Cmd:      gosocks.SocksCmdUDPAssociate,
		HostType: gosocks.SocksIPv4Host,
		DstHost:  "0.0.0.0",
		DstPort:  0,
	})
	cmdUDPAssociateReply, err := gosocks.ReadSocksReply(socks5TcpConn)
	if err != nil {
		socks5TcpConn.Close()
		return nil, nil, err
	}

	if cmdUDPAssociateReply.Rep != gosocks.SocksSucceeded {
		socks5TcpConn.Close()
		return nil, nil, fmt.Errorf("hand err")
	}

	return gosocks.SocksAddrToNetAddr("udp", ip, cmdUDPAssociateReply.BndPort), socks5TcpConn, nil
}
