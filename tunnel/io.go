package tunnel

import (
	"bytes"
	"encoding/binary"
	"io"
	"sync"
)

var DebugTest bool

var rmtxMp map[io.Reader]*sync.Mutex = make(map[io.Reader]*sync.Mutex)
var wmtxMp map[io.Writer]*sync.Mutex = make(map[io.Writer]*sync.Mutex)
var rmtx, wmtx sync.Mutex
var rrw, wrw sync.RWMutex

func read(reader io.Reader, key AESKey) ([]byte, error) {
	if DebugTest {
		rrw.RLock()
		if mtx, ok := rmtxMp[reader]; ok {
			rrw.RUnlock()
			mtx.Lock()
			defer mtx.Unlock()
		} else {
			rrw.RUnlock()
			rrw.Lock()
			mtx = &sync.Mutex{}
			rmtxMp[reader] = mtx
			rrw.Unlock()
			mtx.Lock()
			defer mtx.Unlock()
		}
	} else {
		rmtx.Lock()
		defer rmtx.Unlock()
	}
	//Read Header
	//16 bytes (AES-Block)|32 bytes (sha-256)| 4 bytes (len)
	//Total 52 bytes
	header := make([]byte, 52)
	_, err := reader.Read(header)
	if err != nil {
		return nil, err
	}
	header, err = decrypt(header, key)
	if err != nil {
		return nil, err
	}
	data, err := unhashBuffer(header)
	if err != nil {
		return nil, err
	}
	rd := bytes.NewReader(data)
	var length uint32
	err = binary.Read(rd, binary.LittleEndian, &length)
	if err != nil {
		return nil, err
	}
	data = make([]byte, length)
	_, err = reader.Read(data)
	if err != nil {
		return nil, err
	}
	data, err = decrypt(data, key)
	if err != nil {
		return nil, err
	}
	return unhashBuffer(data)
}

func write(writer io.Writer, data []byte, key AESKey) error {
	if DebugTest {
		wrw.RLock()
		if mtx, ok := wmtxMp[writer]; ok {
			wrw.RUnlock()
			mtx.Lock()
			defer mtx.Unlock()
		} else {
			wrw.RUnlock()
			wrw.Lock()
			mtx = &sync.Mutex{}
			wmtxMp[writer] = mtx
			wrw.Unlock()
			mtx.Lock()
			defer mtx.Unlock()
		}
	} else {
		wmtx.Lock()
		defer wmtx.Unlock()
	}
	//Prepare Body
	data = hashBuffer(data)         //hash data
	data, err := encrypt(data, key) //encrypt data
	if err != nil {
		return err
	}
	//Write Header
	//16 bytes (AES-Block)|32 bytes (sha-256)| 4 bytes (len)
	//Total 52 bytes
	header := new(bytes.Buffer)
	binary.Write(header, binary.LittleEndian, uint32(len(data)))
	hashedHeader := hashBuffer(header.Bytes())
	cipherHeader, err := encrypt(hashedHeader, key)
	if err != nil {
		return err
	}
	_, err = writer.Write(cipherHeader)
	if err != nil {
		return err
	}
	//Write Body
	//16 bytes (AES-Block)|32 bytes (sha-256)| data
	_, err = writer.Write(data)
	return err
}
