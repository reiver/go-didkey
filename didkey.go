package didkey

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"math/big"
	"strings"

	"codeberg.org/reiver/go-erorr"
	"codeberg.org/reiver/go-field"

	"github.com/reiver/go-didkey/internal/base58"
)

const (
	compressedSize   = 33
	uncompressedSize = 65

	// Prefix is what every did:key this package handles starts with.
	Prefix = "did:key:"
)

// KeyType is a key's type (its curve).
type KeyType string

const (
	KeyTypeP256      KeyType = "P-256"
	KeyTypeSecp256k1 KeyType = "secp256k1"
)

// The multicodec codes, as unsigned varints: p256-pub (0x1200) and secp256k1-pub (0xe7).
var (
	multicodecP256      = []byte{0x80, 0x24}
	multicodecSecp256k1 = []byte{0xe7, 0x01}
)

// PublicKey is a P-256 or secp256k1 public key. See the package documentation.
//
// The zero value is not a valid key.
type PublicKey struct {
	keyType      KeyType
	compressed   []byte
	uncompressed []byte
}

// Parse parses a did:key (ex: "did:key:zDnaeTiq1PdzvZXUaMdezchcMJQpBdH2VN4pgrrEhMCCbmwSb").
func Parse(didKey string) (PublicKey, error) {
	if !strings.HasPrefix(didKey, Prefix+"z") {
		return PublicKey{}, erorr.Wrap(ErrBadDIDKey, "bad did:key", field.String("did-key", didKey))
	}
	return ParseMultikey(didKey[len(Prefix):])
}

// ParseMultikey parses a Multikey — the "publicKeyMultibase" of a DID document's Multikey verification method
// (ex: "zDnaeTiq1PdzvZXUaMdezchcMJQpBdH2VN4pgrrEhMCCbmwSb"). It is a did:key without its "did:key:" prefix.
func ParseMultikey(multikey string) (PublicKey, error) {
	if !strings.HasPrefix(multikey, "z") {
		return PublicKey{}, erorr.Wrap(ErrBadMultibase, "bad multibase", field.String("multikey", multikey))
	}

	decoded, err := base58.Decode(multikey[1:])
	if nil != err {
		return PublicKey{}, erorr.Wrap(ErrBadBase58, "bad base58btc", field.String("multikey", multikey))
	}

	var keyType KeyType
	switch {
	case bytes.HasPrefix(decoded, multicodecP256):
		keyType = KeyTypeP256
		decoded = decoded[len(multicodecP256):]
	case bytes.HasPrefix(decoded, multicodecSecp256k1):
		keyType = KeyTypeSecp256k1
		decoded = decoded[len(multicodecSecp256k1):]
	default:
		return PublicKey{}, erorr.Wrap(ErrUnsupportedKeyType, "unsupported multicodec", field.String("multikey", multikey))
	}

	return FromCompressed(keyType, decoded)
}

// FromCompressed returns the public key whose compressed point (0x02 or 0x03, then x — 33 bytes) is 'compressed'.
func FromCompressed(keyType KeyType, compressed []byte) (PublicKey, error) {
	if KeyTypeP256 != keyType && KeyTypeSecp256k1 != keyType {
		return PublicKey{}, erorr.Wrap(ErrUnsupportedKeyType, "unsupported key type", field.String("key-type", string(keyType)))
	}
	if compressedSize != len(compressed) {
		return PublicKey{}, erorr.Wrap(ErrBadKeyLength, "bad key length", field.Int("length", len(compressed)))
	}

	var uncompressed []byte = decompress(keyType, compressed)
	if nil == uncompressed {
		return PublicKey{}, erorr.Wrap(ErrNotOnCurve, "not a valid point on the curve", field.String("key-type", string(keyType)))
	}

	return PublicKey{
		keyType:      keyType,
		compressed:   bytes.Clone(compressed),
		uncompressed: uncompressed,
	}, nil
}

// FromECDSA returns the public key for a P-256 *ecdsa.PublicKey.
func FromECDSA(key *ecdsa.PublicKey) (PublicKey, error) {
	if nil == key {
		return PublicKey{}, ErrNilKey
	}
	if elliptic.P256() != key.Curve {
		return PublicKey{}, ErrNotP256
	}

	ecdhKey, err := key.ECDH()
	if nil != err {
		return PublicKey{}, erorr.Wrap(ErrNotOnCurve, "not a valid point on the curve", field.Error("error", err))
	}
	return FromECDH(ecdhKey)
}

// FromECDH returns the public key for a P-256 *ecdh.PublicKey.
func FromECDH(key *ecdh.PublicKey) (PublicKey, error) {
	if nil == key {
		return PublicKey{}, ErrNilKey
	}
	if ecdh.P256() != key.Curve() {
		return PublicKey{}, ErrNotP256
	}

	var uncompressed []byte = key.Bytes()
	x := new(big.Int).SetBytes(uncompressed[1:33])
	y := new(big.Int).SetBytes(uncompressed[33:])

	return FromCompressed(KeyTypeP256, elliptic.MarshalCompressed(elliptic.P256(), x, y))
}

// Type returns the key's type (its curve).
func (receiver PublicKey) Type() KeyType {
	return receiver.keyType
}

// JWTAlg returns the JWT "alg" for signatures by the key: "ES256" (P-256) or "ES256K" (secp256k1).
func (receiver PublicKey) JWTAlg() string {
	switch receiver.keyType {
	case KeyTypeP256:
		return "ES256"
	case KeyTypeSecp256k1:
		return "ES256K"
	default:
		return ""
	}
}

// Compressed returns the key's compressed point (0x02 or 0x03, then x — 33 bytes).
func (receiver PublicKey) Compressed() []byte {
	return bytes.Clone(receiver.compressed)
}

// Uncompressed returns the key's uncompressed point (0x04, then x, then y — 65 bytes).
// (For P-256, this is what ecdh.P256().NewPublicKey takes.)
func (receiver PublicKey) Uncompressed() []byte {
	return bytes.Clone(receiver.uncompressed)
}

// Multikey returns the key as a Multikey (ex: "zDnae…") — for a DID document's "publicKeyMultibase".
func (receiver PublicKey) Multikey() string {
	var multicodec []byte
	switch receiver.keyType {
	case KeyTypeP256:
		multicodec = multicodecP256
	case KeyTypeSecp256k1:
		multicodec = multicodecSecp256k1
	default:
		return ""
	}

	return "z" + base58.Encode(append(bytes.Clone(multicodec), receiver.compressed...))
}

// DIDKey returns the key as a did:key (ex: "did:key:zDnae…").
func (receiver PublicKey) DIDKey() string {
	var multikey string = receiver.Multikey()
	if "" == multikey {
		return ""
	}
	return Prefix + multikey
}

// String returns the key as a did:key.
func (receiver PublicKey) String() string {
	return receiver.DIDKey()
}

// Equal returns whether two keys are the same.
func (receiver PublicKey) Equal(other PublicKey) bool {
	return receiver.keyType == other.keyType && bytes.Equal(receiver.compressed, other.compressed)
}

// ECDSA returns a P-256 key as an *ecdsa.PublicKey (ex: to verify ES256 signatures).
func (receiver PublicKey) ECDSA() (*ecdsa.PublicKey, error) {
	if KeyTypeP256 != receiver.keyType {
		return nil, ErrNotP256
	}
	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(receiver.uncompressed[1:33]),
		Y:     new(big.Int).SetBytes(receiver.uncompressed[33:]),
	}, nil
}

// ECDH returns a P-256 key as an *ecdh.PublicKey (ex: for HPKE).
func (receiver PublicKey) ECDH() (*ecdh.PublicKey, error) {
	if KeyTypeP256 != receiver.keyType {
		return nil, ErrNotP256
	}
	key, err := ecdh.P256().NewPublicKey(receiver.uncompressed)
	if nil != err {
		return nil, erorr.Wrap(ErrNotOnCurve, "not a valid point on the curve", field.Error("error", err))
	}
	return key, nil
}
