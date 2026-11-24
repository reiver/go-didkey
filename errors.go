package didkey

import (
	"codeberg.org/reiver/go-erorr"
)

const (
	ErrBadBase58         = erorr.Error("didkey: bad base58btc")
	ErrBadDIDKey         = erorr.Error("didkey: bad did:key — must start with \"did:key:z\"")
	ErrBadKeyLength      = erorr.Error("didkey: bad key length — must be a 33-byte compressed point")
	ErrBadMultibase      = erorr.Error("didkey: bad multibase — must start with \"z\" (base58btc)")
	ErrNilKey            = erorr.Error("didkey: nil key")
	ErrNotOnCurve        = erorr.Error("didkey: not a valid point on the curve")
	ErrNotP256           = erorr.Error("didkey: not a P-256 key")
	ErrUnsupportedKeyType = erorr.Error("didkey: unsupported key type — must be P-256 or secp256k1")
)
