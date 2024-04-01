package tunnel

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

type AESKey []byte

func NewAESKey() (AESKey, error) {
	key := make(AESKey, 32) // AES-256 requiere una clave de 32 bytes
	_, err := io.ReadFull(rand.Reader, key)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func (key AESKey) ToString() string {
	str := ""
	for i := 0; i < 31; i++ {
		str += fmt.Sprintf("%d,", key[i])
	}
	str += fmt.Sprintf("%d", key[31])
	return str
}

func KeyFromStr(str string) (AESKey, error) {
	key := make(AESKey, 32)
	splited := strings.SplitN(str, ",", 32)
	if len(splited) != 32 {
		return nil, errors.New("key is too short")
	}
	for i := 0; i < 32; i++ {
		if value, err := strconv.Atoi(splited[i]); err != nil {
			return nil, err
		} else {
			key[i] = byte(value)
		}
	}
	return key, nil
}

func encrypt(buffer []byte, key AESKey) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	cipherBuffer := make([]byte, aes.BlockSize+len(buffer))
	iv := cipherBuffer[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(cipherBuffer[aes.BlockSize:], buffer)
	return cipherBuffer, nil
}

func decrypt(buffer []byte, key AESKey) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(buffer) < aes.BlockSize {
		return nil, ErrCipherTextShort
	}
	iv := buffer[:aes.BlockSize]
	cipherBuffer := buffer[aes.BlockSize:]
	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(cipherBuffer, cipherBuffer)
	return cipherBuffer, nil
}

// GenerarHashSHA256 genera un hash SHA-256 a partir de un buffer de bytes.
func GetHashSHA256(data []byte) []byte {
	hash := sha256.Sum256(data)
	return hash[:]
}

// VerificarHashSHA256 verifica si un buffer coincide con un hash SHA-256 dado.
func CheckHashSHA256(data []byte, hash []byte) bool {
	newHash := GetHashSHA256(data)
	return string(newHash) == string(hash)
}

func hashBuffer(buffer []byte) []byte {
	hash := GetHashSHA256(buffer)
	hashedBuffer := make([]byte, len(hash)+len(buffer))
	copy(hashedBuffer[:len(hash)], hash)
	copy(hashedBuffer[len(hash):], buffer)
	return hashedBuffer
}

func unhashBuffer(buffer []byte) ([]byte, error) {
	hash := buffer[:32]
	unhashedBuffer := buffer[32:]
	if CheckHashSHA256(unhashedBuffer, hash) {
		return unhashedBuffer, nil
	}
	return nil, ErrHashMissmathed
}
