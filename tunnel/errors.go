package tunnel

import "errors"

var ErrHashMissmathed = errors.New("hash missmatched!!")
var ErrCipherTextShort = errors.New("cipher text is too short")
var ErrInvalidChunkSize = errors.New("chunk size has to be greater than 6 bytes")
