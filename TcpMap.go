package main

import (
	"sync"
)

/*
此Map用于储存  一条链接的最终目的地址  和发起请求的进程ID

key为本地端口
*/

// TcpMap
type TcpMap struct {
	Map  map[int]TcpMapInfo
	lock *sync.RWMutex // 加锁
}

type TcpMapInfo struct {
	pid uint64 //进程id
	ip  []byte //连接的目标地址
}

func NewTcpMap() *TcpMap {
	return &TcpMap{Map: make(map[int]TcpMapInfo), lock: new(sync.RWMutex)}
}

// Set ...
func (m *TcpMap) Set(key int, pid uint64, ip []byte) {
	m.lock.Lock()
	defer m.lock.Unlock()
	m.Map[key] = TcpMapInfo{pid: pid, ip: ip}
}

//Del
func (m *TcpMap) Del(key int) {
	m.lock.Lock()
	defer m.lock.Unlock()
	delete(m.Map, key)
}

// Get ...
func (m *TcpMap) Get(key int) (a TcpMapInfo, b bool) {
	m.lock.RLock()
	defer m.lock.RUnlock()
	a, b = m.Map[key]
	return
}
