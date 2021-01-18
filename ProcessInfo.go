package main

import (
	"sync"
)

/*
此Map用于储存进程的流量信息

key为进程id
*/

type mMap struct {
	Map  map[uint64]mInfo
	lock *sync.RWMutex // 加锁
}

type mInfo struct {
	send int64 //发送量
	recv int64 //接收量
}

func NewProcessMap() *mMap {
	return &mMap{Map: make(map[uint64]mInfo), lock: new(sync.RWMutex)}
}

// 添加流量统计
func (m *mMap) Add(key uint64, send int64, recv int64) {
	m.lock.Lock()
	defer m.lock.Unlock()

	c := m.Map[key]
	m.Map[key] = mInfo{send: c.send + send, recv: c.recv + recv}

}

//Del
func (m *mMap) Del(key uint64) {
	m.lock.Lock()
	defer m.lock.Unlock()
	delete(m.Map, key)
}

// Get ...
func (m *mMap) Get(key uint64) mInfo {
	m.lock.Lock()
	defer m.lock.Unlock()
	return m.Map[key]
}
