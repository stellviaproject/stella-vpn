package tunnel

import (
	"bytes"
	"encoding/binary"
	"io"
	"log"
	"net"
)

type ReqType int

const (
	LOOKUP  ReqType = 0
	WRITE   ReqType = 1
	CLOSE   ReqType = 2
	CONNECT ReqType = 3
)

type ResType int

const (
	CONNECT_RES ResType = 4
	LOOKUP_RES  ResType = 3
	WRITE_RES   ResType = 2
	READ_RES    ResType = 1
	CLOSE_RES   ResType = 0
)

func (addTyp AddrType) toNetwork() string {
	switch addTyp {
	case IPAddr:
		return "ip"
	case TCPAddr:
		return "tcp"
	case UDPAddr:
		return "udp"
	case UnixAddr:
		return "unix"
	default:
		log.Panicln("not implemented protocol")
	}
	return ""
}

func toAddrType(network string) AddrType {
	var networkKind AddrType
	switch network {
	case "ip":
		networkKind = IPAddr
	case "tcp":
		networkKind = TCPAddr
	case "udp":
		networkKind = UDPAddr
	case "unix":
		networkKind = UnixAddr
	default:
		log.Panicf("not implemented protocol '%s'\n", network)
	}
	return networkKind
}

type TunnelReq struct {
	ID      int
	Network AddrType
	Type    ReqType
	Data    []byte
}

func (req *TunnelReq) Equal(other *TunnelReq) bool {
	if len(other.Data) != len(req.Data) {
		return false
	}
	for i := 0; i < len(other.Data); i++ {
		if other.Data[i] != req.Data[i] {
			return false
		}
	}
	return req.ID == other.ID && req.Network == other.Network && req.Type == other.Type
}

func NewDialReq(id int, network, address string) *TunnelReq {
	return &TunnelReq{
		ID:      id,
		Network: toAddrType(network),
		Type:    LOOKUP,
		Data:    []byte(address),
	}
}

func NewDialRes(id int, local, remote net.Addr, err error) *TunnelRes {
	if err != nil {
		return &TunnelRes{
			ID:         id,
			LocalAddr:  &Addr{},
			RemoteAddr: &Addr{},
			Err:        err.Error(),
			Type:       LOOKUP_RES,
			Data:       []byte{},
		}
	}
	return &TunnelRes{
		ID:         id,
		LocalAddr:  toTunnelAddr(local),
		RemoteAddr: toTunnelAddr(remote),
		Err:        "",
		Type:       LOOKUP_RES,
		Data:       []byte{},
	}
}

func NewWriteReq(id int, network string, data []byte) *TunnelReq {
	return &TunnelReq{
		ID:      id,
		Network: toAddrType(network),
		Type:    WRITE,
		Data:    data,
	}
}

func NewWriteRes(id int, local, remote net.Addr, err error) *TunnelRes {
	if err != nil {
		return &TunnelRes{
			ID:         id,
			LocalAddr:  toTunnelAddr(local),
			RemoteAddr: toTunnelAddr(remote),
			Type:       WRITE_RES,
			Err:        err.Error(),
			Data:       []byte{},
		}
	}
	return &TunnelRes{
		ID:         id,
		LocalAddr:  toTunnelAddr(local),
		RemoteAddr: toTunnelAddr(remote),
		Type:       WRITE_RES,
		Data:       []byte{},
	}
}

func NewReadRes(id int, local, remote net.Addr, data []byte, err error) *TunnelRes {
	if err != nil {
		return &TunnelRes{
			ID:         id,
			LocalAddr:  toTunnelAddr(local),
			RemoteAddr: toTunnelAddr(remote),
			Type:       READ_RES,
			Err:        err.Error(),
			Data:       []byte{},
		}
	}
	return &TunnelRes{
		ID:         id,
		LocalAddr:  toTunnelAddr(local),
		RemoteAddr: toTunnelAddr(remote),
		Type:       READ_RES,
		Data:       data,
	}
}

func NewCloseReq(id int, network, address string) *TunnelReq {
	return &TunnelReq{
		ID:      id,
		Network: toAddrType(network),
		Type:    CLOSE,
		Data:    []byte{},
	}
}

func NewCloseRes(id int, local, remote net.Addr, err error) *TunnelRes {
	if err != nil {
		return &TunnelRes{
			ID:         id,
			LocalAddr:  toTunnelAddr(local),
			RemoteAddr: toTunnelAddr(remote),
			Type:       CLOSE_RES,
			Err:        err.Error(),
			Data:       []byte{},
		}
	}
	return &TunnelRes{
		ID:         id,
		LocalAddr:  toTunnelAddr(local),
		RemoteAddr: toTunnelAddr(remote),
		Type:       CLOSE_RES,
		Data:       []byte{},
	}
}

func NewConnectReq() *TunnelReq {
	return &TunnelReq{
		ID:      0,
		Network: IPAddr,
		Type:    CONNECT,
		Data:    []byte{},
	}
}

func NewConnectRes() *TunnelRes {
	return &TunnelRes{
		ID:         0,
		LocalAddr:  &Addr{},
		RemoteAddr: &Addr{},
		Type:       CONNECT_RES,
		Data:       []byte{},
	}
}

func (req *TunnelReq) Write(w io.Writer, key AESKey) error {
	buffer := &bytes.Buffer{}
	err := binary.Write(buffer, binary.LittleEndian, uint16(req.ID))
	if err != nil {
		return err
	}
	err = binary.Write(buffer, binary.LittleEndian, int8(req.Network))
	if err != nil {
		return err
	}
	err = binary.Write(buffer, binary.LittleEndian, int8(req.Type))
	if err != nil {
		return err
	}
	err = binary.Write(buffer, binary.LittleEndian, uint16(len(req.Data)))
	if err != nil {
		return err
	}
	err = binary.Write(buffer, binary.LittleEndian, req.Data)
	if err != nil {
		return err
	}
	return write(w, buffer.Bytes(), key)
}

func (req *TunnelReq) Read(r io.Reader, key AESKey) error {
	data, err := read(r, key)
	if err != nil {
		return err
	}
	var id uint16
	var network int8
	var typ int8
	var length uint16
	reader := bytes.NewReader(data)
	err = binary.Read(reader, binary.LittleEndian, &id)
	if err != nil {
		return err
	}
	err = binary.Read(reader, binary.LittleEndian, &network)
	if err != nil {
		return err
	}
	err = binary.Read(reader, binary.LittleEndian, &typ)
	if err != nil {
		return err
	}
	err = binary.Read(reader, binary.LittleEndian, &length)
	if err != nil {
		return err
	}
	data = make([]byte, length)
	err = binary.Read(reader, binary.LittleEndian, data)
	if err != nil {
		return err
	}
	req.ID = int(id)
	req.Network = AddrType(network)
	req.Type = ReqType(typ)
	req.Data = data
	return nil
}

type TunnelRes struct {
	ID         int
	LocalAddr  *Addr
	RemoteAddr *Addr
	Err        string
	Type       ResType
	Data       []byte
}

func (res *TunnelRes) Equal(other *TunnelRes) bool {
	if len(other.Data) != len(res.Data) {
		return false
	}
	for i := 0; i < len(other.Data); i++ {
		if other.Data[i] != res.Data[i] {
			return false
		}
	}
	return res.LocalAddr.Equal(other.LocalAddr) &&
		res.RemoteAddr.Equal(other.RemoteAddr) &&
		res.ID == other.ID &&
		res.Err == other.Err &&
		res.Type == other.Type
}

func (res *TunnelRes) Write(w io.Writer, key AESKey) error {
	buffer := &bytes.Buffer{}
	err := binary.Write(buffer, binary.LittleEndian, uint16(res.ID))
	if err != nil {
		return err
	}
	err = res.LocalAddr.Write(buffer, key)
	if err != nil {
		return err
	}
	err = res.RemoteAddr.Write(buffer, key)
	if err != nil {
		return err
	}
	errMsg := []byte(res.Err)
	errMsgLen := uint16(len(errMsg))
	err = binary.Write(buffer, binary.LittleEndian, errMsgLen)
	if err != nil {
		return err
	}
	err = binary.Write(buffer, binary.LittleEndian, errMsg)
	if err != nil {
		return err
	}
	err = binary.Write(buffer, binary.LittleEndian, uint8(res.Type))
	if err != nil {
		return err
	}
	// err = binary.Write(buffer, binary.LittleEndian, uint64(res.ReadBytes))
	// if err != nil {
	// 	return err
	// }
	// err = binary.Write(buffer, binary.LittleEndian, uint64(res.WriteBytes))
	// if err != nil {
	// 	return err
	// }
	err = binary.Write(buffer, binary.LittleEndian, uint16(len(res.Data)))
	if err != nil {
		return err
	}
	err = binary.Write(buffer, binary.LittleEndian, res.Data)
	if err != nil {
		return err
	}
	return write(w, buffer.Bytes(), key)
}

func (res *TunnelRes) Read(r io.Reader, key AESKey) error {
	data, err := read(r, key)
	if err != nil {
		return err
	}
	reader := bytes.NewReader(data)
	var id uint16
	err = binary.Read(reader, binary.LittleEndian, &id)
	if err != nil {
		return err
	}
	localAddr := new(Addr)
	err = localAddr.Read(reader, key)
	if err != nil {
		return err
	}
	remoteAddr := new(Addr)
	err = remoteAddr.Read(reader, key)
	if err != nil {
		return err
	}
	var errMsgLen uint16
	err = binary.Read(reader, binary.LittleEndian, &errMsgLen)
	if err != nil {
		return err
	}
	errMsg := make([]byte, errMsgLen)
	err = binary.Read(reader, binary.LittleEndian, errMsg)
	if err != nil {
		return err
	}
	var typ uint8
	err = binary.Read(reader, binary.LittleEndian, &typ)
	if err != nil {
		return err
	}
	// var readBytes uint8
	// err = binary.Read(reader, binary.LittleEndian, &readBytes)
	// if err != nil {
	// 	return err
	// }
	// var writeBytes uint8
	// err = binary.Read(reader, binary.LittleEndian, &writeBytes)
	// if err != nil {
	// 	return err
	// }
	var dataLen uint16
	err = binary.Read(reader, binary.LittleEndian, &dataLen)
	if err != nil {
		return err
	}
	data = make([]byte, dataLen)
	err = binary.Read(reader, binary.LittleEndian, data)
	if err != nil {
		return err
	}
	res.ID = int(id)
	res.LocalAddr = localAddr
	res.RemoteAddr = remoteAddr
	// res.ReadBytes = int(readBytes)
	// res.WriteBytes = int(writeBytes)
	res.Err = string(errMsg)
	res.Type = ResType(typ)
	res.Data = data
	return nil
}

type AddrType int

const (
	IPAddr   AddrType = 0
	TCPAddr  AddrType = 1
	UDPAddr  AddrType = 2
	UnixAddr AddrType = 3
)

type Addr struct {
	Type AddrType
	IP   []byte
	Port int
	Zone string
	Name string
	Net  string
}

func (a *Addr) Equal(other *Addr) bool {
	if len(a.IP) != len(other.IP) {
		return false
	}
	for i := 0; i < len(a.IP); i++ {
		if a.IP[i] != other.IP[i] {
			return false
		}
	}
	return a.Type == other.Type && a.Port == other.Port && a.Name == other.Name && a.Zone == other.Zone && a.Net == other.Net
}

func (a *Addr) Read(r io.Reader, key AESKey) error {
	var typ int8
	err := binary.Read(r, binary.LittleEndian, &typ)
	if err != nil {
		return err
	}
	var ipLen uint8
	err = binary.Read(r, binary.LittleEndian, &ipLen)
	if err != nil {
		return err
	}
	ip := make([]byte, ipLen)
	err = binary.Read(r, binary.LittleEndian, ip)
	if err != nil {
		return err
	}
	var port uint16
	err = binary.Read(r, binary.LittleEndian, &port)
	if err != nil {
		return err
	}
	var zoneLen uint8
	err = binary.Read(r, binary.LittleEndian, &zoneLen)
	if err != nil {
		return err
	}
	zone := make([]byte, zoneLen)
	err = binary.Read(r, binary.LittleEndian, zone)
	if err != nil {
		return err
	}
	var nameLen uint8
	err = binary.Read(r, binary.LittleEndian, &nameLen)
	if err != nil {
		return err
	}
	name := make([]byte, nameLen)
	err = binary.Read(r, binary.LittleEndian, name)
	if err != nil {
		return err
	}
	var netLen uint8
	err = binary.Read(r, binary.LittleEndian, &netLen)
	if err != nil {
		return err
	}
	net := make([]byte, netLen)
	err = binary.Read(r, binary.LittleEndian, net)
	if err != nil {
		return err
	}
	a.IP = ip
	a.Name = string(name)
	a.Net = string(net)
	a.Port = int(port)
	a.Type = AddrType(typ)
	a.Zone = string(zone)
	return nil
}

func (a *Addr) Write(w io.Writer, key AESKey) error {
	typ := int8(a.Type)
	err := binary.Write(w, binary.LittleEndian, typ)
	if err != nil {
		return err
	}
	ipLen := uint8(len(a.IP))
	err = binary.Write(w, binary.LittleEndian, ipLen)
	if err != nil {
		return err
	}
	err = binary.Write(w, binary.LittleEndian, a.IP)
	if err != nil {
		return err
	}
	port := uint16(a.Port)
	err = binary.Write(w, binary.LittleEndian, port)
	if err != nil {
		return err
	}
	zone := []byte(a.Zone)
	zoneLen := uint8(len(zone))
	err = binary.Write(w, binary.LittleEndian, zoneLen)
	if err != nil {
		return err
	}
	err = binary.Write(w, binary.LittleEndian, zone)
	if err != nil {
		return err
	}
	name := []byte(a.Name)
	nameLen := uint8(len(name))
	err = binary.Write(w, binary.LittleEndian, nameLen)
	if err != nil {
		return err
	}
	err = binary.Write(w, binary.LittleEndian, name)
	if err != nil {
		return err
	}
	net := []byte(a.Net)
	netLen := uint8(len(net))
	err = binary.Write(w, binary.LittleEndian, netLen)
	if err != nil {
		return err
	}
	return binary.Write(w, binary.LittleEndian, net)
}

func (a *Addr) toNetAddr() net.Addr {
	switch a.Type {
	case IPAddr:
		return &net.IPAddr{
			IP:   a.IP,
			Zone: a.Zone,
		}
	case TCPAddr:
		return &net.TCPAddr{
			IP:   a.IP,
			Port: a.Port,
			Zone: a.Zone,
		}
	case UDPAddr:
		return &net.UDPAddr{
			IP:   a.IP,
			Port: a.Port,
			Zone: a.Zone,
		}
	case UnixAddr:
		return &net.UnixAddr{
			Name: a.Name,
			Net:  a.Net,
		}
	default:
		log.Panicln("not implemented protocol")
	}
	return nil
}

func toTunnelAddr(addr net.Addr) *Addr {
	switch v := addr.(type) {
	case *net.IPAddr:
		return &Addr{
			Type: IPAddr,
			IP:   v.IP,
			Zone: v.Zone,
		}
	case *net.TCPAddr:
		return &Addr{
			Type: TCPAddr,
			IP:   v.IP,
			Port: v.Port,
			Zone: v.Zone,
		}
	case *net.UDPAddr:
		return &Addr{
			Type: UDPAddr,
			IP:   v.IP,
			Port: v.Port,
			Zone: v.Zone,
		}
	case *net.UnixAddr:
		return &Addr{
			Type: UnixAddr,
			Name: v.Name,
			Net:  v.Net,
		}
	default:
		log.Panicf("not implemented for addr of type: %s\n", v)
	}
	return nil
}
