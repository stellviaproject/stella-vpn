package tunnel

import (
	"bytes"
	"testing"
)

func TestRequest(t *testing.T) {
	key, err := NewAESKey()
	if err != nil {
		t.FailNow()
	}
	buffer := &bytes.Buffer{}
	req := &TunnelReq{
		ID:      101,
		Network: TCPAddr,
		Type:    CONNECT,
		Data:    []byte("hello world everybody!!!"),
	}
	err = req.Write(buffer, key)
	if err != nil {
		t.FailNow()
	}
	reader := bytes.NewReader(buffer.Bytes())
	other := &TunnelReq{}
	err = other.Read(reader, key)
	if err != nil {
		t.FailNow()
	}
	if !other.Equal(req) {
		t.FailNow()
	}
}

func TestResponse(t *testing.T) {
	key, err := NewAESKey()
	if err != nil {
		t.FailNow()
	}
	buffer := &bytes.Buffer{}
	res := &TunnelRes{
		ID: 101,
		LocalAddr: &Addr{
			Type: TCPAddr,
			IP:   []byte{10, 0, 0, 1},
			Port: 8080,
			Zone: "CU",
			Name: "local",
			Net:  "network",
		},
		RemoteAddr: &Addr{
			Type: TCPAddr,
			IP:   []byte{12, 1, 5, 1},
			Port: 443,
			Zone: "US",
			Name: "remote",
			Net:  "network",
		},
		Err:  "some errors!!",
		Type: LOOKUP_RES,
		Data: []byte("hello world everybody!!!"),
	}
	err = res.Write(buffer, key)
	if err != nil {
		t.FailNow()
	}
	other := &TunnelRes{}
	reader := bytes.NewReader(buffer.Bytes())
	err = other.Read(reader, key)
	if err != nil {
		t.FailNow()
	}
	if !other.Equal(res) {
		t.FailNow()
	}
}
