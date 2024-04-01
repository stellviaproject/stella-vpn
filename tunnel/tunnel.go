package tunnel

import (
	"errors"
	"io"
	"log"
	"net"
	"sync"
	"time"
)

type ConnHandler struct {
	id               int
	network, address string
	localAddr        net.Addr
	remoteAddr       net.Addr
	wres, rres, cres chan *TunnelRes
	target           net.Conn
	key              AESKey
	retry            int
	connErr          chan error
	release          func(id int)
}

func (handler *ConnHandler) Read(b []byte) (n int, err error) {
	res := <-handler.rres
	if res.Err == io.EOF.Error() {
		handler.release(handler.id)
		copy(b, res.Data)
		return len(res.Data), io.EOF
	}
	if res.Err != "" {
		handler.release(handler.id)
		return 0, errors.New(res.Err)
	}
	copy(b, res.Data)
	//log.Println("len(b):", len(b), "len(data):", len(res.Data))
	return len(res.Data), nil
}

func (handler *ConnHandler) Write(b []byte) (n int, err error) {
	req := NewWriteReq(handler.id, handler.network, b)
	err = req.Write(handler.target, handler.key)
	if err != nil {
		handler.release(handler.id)
		handler.connErr <- err
		return
	}
	res := <-handler.wres
	if res.Err != "" {
		handler.release(handler.id)
		return 0, errors.New(res.Err)
	}
	n = len(b)
	return
}

func (handler *ConnHandler) Close() error {
	req := NewCloseReq(handler.id, handler.network, handler.address)
	err := req.Write(handler.target, handler.key)
	defer handler.release(handler.id)
	if err != nil {
		handler.connErr <- err
		return err
	}
	res := <-handler.cres
	if res.Err != "" {
		return errors.New(res.Err)
	}
	return nil
}

func (handler *ConnHandler) LocalAddr() net.Addr {
	return handler.localAddr
}

func (handler *ConnHandler) RemoteAddr() net.Addr {
	return handler.remoteAddr
}

func (c *ConnHandler) SetDeadline(t time.Time) error {
	// Implementa la lógica para establecer el tiempo de espera aquí
	return errors.New("not implemented")
}

func (c *ConnHandler) SetReadDeadline(t time.Time) error {
	// Implementa la lógica para establecer el tiempo de espera de lectura aquí
	return errors.New("not implemented")
}

func (c *ConnHandler) SetWriteDeadline(t time.Time) error {
	// Implementa la lógica para establecer el tiempo de espera de escritura aquí
	return errors.New("not implemented")
}

func (handler *ConnHandler) fill(res *TunnelRes) {
	handler.localAddr = res.LocalAddr.toNetAddr()
	handler.remoteAddr = res.RemoteAddr.toNetAddr()
}

func (handler *ConnHandler) handle(conn net.Conn) {
	// handler.cres = make(chan *TunnelRes)
	log.Printf("[handle] handling connection read to %s\n", handler.address)
	buffer := make([]byte, 4096)
	hasReaded := 0
	for {
		readed, err := handler.target.Read(buffer)
		if err != nil {
			if err == io.EOF {
				if hasReaded != 0 {
					log.Printf("[handle] read EOF from %s\n", handler.address)
					// handler.cres <- nil
					handler.writeErr(err, conn)
					return
				} else {
					log.Printf("[handle] read retry on %s\n", handler.retry)
					handler.retry++
				}
			} else {
				// handler.cres <- nil
				log.Printf("[handle] read error on %s\n", handler.address)
				handler.writeErr(err, conn)
				return
			}
		} else {
			hasReaded += readed
			log.Printf("[handle] read succes then write to tunnel\n")
			res := NewReadRes(handler.id, handler.localAddr, handler.remoteAddr, buffer[:readed], err)
			err = res.Write(conn, handler.key)
			if err != nil {
				log.Printf("[handle] writing to tunnel failed\n")
				handler.connErr <- err
				return
			}
		}
	}
}

// func (handler *ConnHandler) waitForRead() {
// 	<-handler.cres
// }

func (handler *ConnHandler) writeErr(err error, conn net.Conn) {
	log.Printf("[writeErr] writing error for connection to %s\n", err.Error())
	res := NewReadRes(handler.id, handler.localAddr, handler.remoteAddr, nil, err)
	err = res.Write(conn, handler.key)
	if err != nil {
		log.Printf("[writeErr] error in tunnel connection\n")
		handler.connErr <- err
		return
	}
}

type Tunnel struct {
	conn         net.Conn
	connHandlers map[int]*ConnHandler
	key          AESKey
	connErr      chan error
	connectTime  time.Duration
	rw           sync.RWMutex
	sg, lk       chan int
}

func NewTunnel(conn net.Conn, key AESKey) *Tunnel {
	return &Tunnel{
		conn:         conn,
		connHandlers: make(map[int]*ConnHandler, 128),
		key:          key,
		connErr:      make(chan error),
		connectTime:  time.Millisecond * 100,
		sg:           make(chan int),
		lk:           make(chan int),
	}
}

func (t *Tunnel) RunClient() {
	go t.loopResponse()
	<-t.lk
}

func (t *Tunnel) RunServer() {
	go t.loopRequest()
	<-t.lk
}

func (t *Tunnel) Stop() {
	t.sg <- 0
}

func (t *Tunnel) loopResponse() {
	var err error
	run := true
	for err == nil && run {
		if run, err = t.checkExit(); err != nil || !run {
			continue
		}
		res := &TunnelRes{}
		err = res.Read(t.conn, t.key)
		if err != nil {
			break
		}
		switch res.Type {
		case CONNECT_RES:
			go t.DoConnectReq()
			continue
		case WRITE_RES, LOOKUP_RES:
			if res.Type == WRITE_RES {
				log.Println("receive write response")
			} else {
				log.Println("receive lookup response")
			}
			t.rw.RLock()
			conn := t.connHandlers[res.ID]
			t.rw.RUnlock()
			if conn != nil {
				conn.wres <- res
			}
			continue
		case READ_RES:
			log.Println("receive read response")
			t.rw.RLock()
			conn := t.connHandlers[res.ID]
			t.rw.RUnlock()
			if conn != nil {
				conn.rres <- res
			}
			continue
		case CLOSE_RES:
			log.Println("receive close response")
			t.rw.RLock()
			conn := t.connHandlers[res.ID]
			t.rw.RUnlock()
			if conn != nil {
				conn.cres <- res
			}
			continue
		}
	}
	if err != nil {
		log.Println(err)
	}
	t.lk <- 0
}

func (t *Tunnel) checkExit() (bool, error) {
	select {
	case <-t.sg:
		return false, nil
	default:
	}
	t.rw.RLock()
	defer t.rw.RUnlock()
	for _, conn := range t.connHandlers {
		select {
		case err := <-conn.connErr:
			return false, err
		default:
		}
	}
	return true, nil
}

func (t *Tunnel) loopRequest() {
	log.Println("listening request throught tunnel...")
	var err error
	run := true
	for err == nil && run {
		log.Printf("[loopRequest] checking exit\n")
		if run, err = t.checkExit(); err != nil || !run {
			log.Printf("[loopRequest] continue to exit\n")
			continue
		}
		req := &TunnelReq{}
		log.Printf("[loopRequest] waiting for request\n")
		err = req.Read(t.conn, t.key)
		if err != nil {
			break
		}
		switch req.Type {
		case LOOKUP:
			log.Printf("[loopRequest] receiving lookup request to %s\n", string(req.Data))
			go t.doDialRes(req)
			continue
		case WRITE:
			log.Printf("[loopRequest] receiving write request to %s\n", string(req.Data))
			go t.doWrite(req)
			continue
		case CLOSE:
			log.Printf("[loopRequest] receiving close request to %s\n", string(req.Data))
			go t.doClose(req)
			continue
		case CONNECT:
			log.Printf("[loopRequest] receiving connect request to %s\n", string(req.Data))
			go t.DoConnectRes()
			continue
		}
	}
	if err != nil {
		log.Printf("[loopRequest] some error with tunnel connection\n")
		log.Println(err)
	}
	t.lk <- 0
}

func (t *Tunnel) doDialRes(req *TunnelReq) {
	network := req.Network.toNetwork()
	address := string(req.Data)
	log.Printf("[doDialRes] doing dial to %s\n", address)
	conn, err := net.Dial(network, address)
	if err != nil {
		log.Printf("[doDialRes] dial failed with error: %s\n", err.Error())
		res := NewDialRes(req.ID, nil, nil, err)
		err = res.Write(t.conn, t.key)
		if err != nil {
			t.connErr <- err
			return
		}
		return
	}
	log.Printf("[doDialRes] dial success with remote address %s\n", conn.RemoteAddr().String())
	res := NewDialRes(req.ID, conn.LocalAddr(), conn.RemoteAddr(), err)
	err = res.Write(t.conn, t.key)
	if err != nil {
		log.Printf("[doDialRes] failed to write response on tunnel")
		t.connErr <- err
		return
	}
	t.handleConn(req, conn)
}

func (t *Tunnel) doWrite(req *TunnelReq) {
	t.rw.Lock()
	handler := t.connHandlers[req.ID]
	t.rw.Unlock()
	log.Printf("writing data on %s\n", handler.address)
	_, err := handler.target.Write(req.Data)
	res := NewWriteRes(req.ID, handler.localAddr, handler.remoteAddr, err)
	err = res.Write(t.conn, t.key)
	if err != nil {
		log.Printf("[doWrite] writing response to tunnel failed\n")
		t.connErr <- err
	}
}

func (t *Tunnel) doClose(req *TunnelReq) {
	t.rw.Lock()
	handler := t.connHandlers[req.ID]
	delete(t.connHandlers, req.ID)
	t.rw.Unlock()
	// handler.waitForRead()
	log.Printf("[doClose] closing connection to %s\n", handler.address)
	err := handler.target.Close()
	res := NewCloseRes(req.ID, handler.localAddr, handler.remoteAddr, err)
	err = res.Write(t.conn, t.key)
	if err != nil {
		log.Printf("[doClose] writing response to tunnel failed\n")
		t.connErr <- err
		return
	}
}

func (t *Tunnel) DoConnectReq() {
	time.Sleep(t.connectTime)
	req := NewConnectReq()
	err := req.Write(t.conn, t.key)
	if err != nil {
		t.connErr <- err
	}
}

func (t *Tunnel) DoConnectRes() {
	time.Sleep(t.connectTime)
	res := NewConnectRes()
	err := res.Write(t.conn, t.key)
	if err != nil {
		t.connErr <- err
	}
}

func (t *Tunnel) newConnHandler(network, address string) *ConnHandler {
	t.rw.Lock()
	defer t.rw.Unlock()
	id := -1
	for i := 0; id == -1 && i < len(t.connHandlers); i++ {
		if _, ok := t.connHandlers[i]; !ok {
			id = i
		}
	}
	if id == -1 {
		id = len(t.connHandlers)
	}
	conn := &ConnHandler{
		id:      id,
		network: network,
		address: address,
		wres:    make(chan *TunnelRes, 128),
		rres:    make(chan *TunnelRes, 128),
		cres:    make(chan *TunnelRes, 128),
		target:  t.conn,
		key:     t.key,
		connErr: make(chan error),
		release: func(id int) {
			t.rw.Lock()
			defer t.rw.Unlock()
			delete(t.connHandlers, id)
		},
	}
	t.connHandlers[id] = conn
	return conn
}

func (t *Tunnel) handleConn(req *TunnelReq, conn net.Conn) {
	t.rw.Lock()
	defer t.rw.Unlock()
	handler := &ConnHandler{
		id:         req.ID,
		network:    req.Network.toNetwork(),
		address:    string(req.Data),
		localAddr:  conn.LocalAddr(),
		remoteAddr: conn.RemoteAddr(),
		target:     conn,
		connErr:    make(chan error),
		key:        t.key,
	}
	t.connHandlers[req.ID] = handler
	go handler.handle(t.conn)
}

func (t *Tunnel) Dial(network, address string) (net.Conn, error) {
	conn := t.newConnHandler(network, address)
	req := NewDialReq(conn.id, network, address)
	if err := req.Write(t.conn, t.key); err != nil {
		return nil, err
	}
	res := <-conn.wres
	if res.Err != "" {
		return nil, errors.New(res.Err)
	}
	conn.fill(res)
	return conn, nil
}
