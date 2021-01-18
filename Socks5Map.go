package main

import (
	"net"
	"sync"
)

/*
此map用于保存socks5udp的我受请求和握手端口
key 为驱动id

*/
type su struct {
	conn   net.Conn //UDP的握手请求
	server net.Addr // server地址
}

// socks5UdpMap
type suMap struct {
	Map  map[int64]su
	lock *sync.RWMutex // 加锁
}

func NewSuMap() *suMap {
	return &suMap{Map: make(map[int64]su), lock: new(sync.RWMutex)}
}

// Set ...
func (m *suMap) Set(key int64, conn net.Conn, server net.Addr) {
	m.lock.Lock()
	defer m.lock.Unlock()
	m.Map[key] = su{conn: conn, server: server}
}

//Del
func (m *suMap) Del(key int64) {
	m.lock.Lock()
	defer m.lock.Unlock()

	if a, ok := m.Map[key]; ok {

		//握手连接存在
		if a.conn != nil {
			a.conn.Close()
		}
	}
	delete(m.Map, key)
}

//DelAll
func (m *suMap) DelAll() {
	m.lock.Lock()
	defer m.lock.Unlock()

	//遍历Map  断开所有socks5握手连接
	for k, v := range m.Map {
		v.conn.Close()
		delete(m.Map, k)

	}
}

// Get ...
func (m *suMap) Get(key int64) (a su, b bool) {
	m.lock.RLock()
	defer m.lock.RUnlock()
	a, b = m.Map[key]
	return
}

/*
func main() {

	as := NewSuMap()

	for i := 0; i < 500; i++ {

		conn, err := net.DialTimeout("tcp", "47.102.149.3:1080", time.Second*2)
		if err != nil {
			fmt.Println(err)
			return
		}
		addr, err := net.ResolveUDPAddr("udp", "47.102.149.3:1080")
		if err != nil {
			fmt.Println(err)
			return
		}

		as.Set(int64(i), conn, addr)

		go func(abc int64) {
			time.Sleep(20 * time.Second)
			defer as.Del(abc)
			fmt.Println("del", abc)
		}(int64(i))

		fmt.Println(int64(i))

	}

	select {}
}
*/
