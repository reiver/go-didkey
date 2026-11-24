package didkey_test

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"strings"
	"testing"

	"github.com/reiver/go-didkey"
	"github.com/reiver/go-didkey/internal/base58"
)

func loadJSON(t *testing.T, filename string, v any) {
	t.Helper()

	data, err := os.ReadFile(filename)
	if nil != err {
		t.Fatalf("Did not expect an error but actually got one: (%T) %s", err, err)
	}
	if err := json.Unmarshal(data, v); nil != err {
		t.Fatalf("Did not expect an error but actually got one: (%T) %s", err, err)
	}
}

func TestInterop_P256(t *testing.T) {
	var vectors []struct {
		PrivateKeyBytesBase58 string `json:"privateKeyBytesBase58"`
		PublicDidKey          string `json:"publicDidKey"`
	}
	loadJSON(t, "testdata/w3c_didkey_P256.json", &vectors)
	if 0 == len(vectors) {
		t.Fatal("Expected some vectors.")
	}

	for _, vector := range vectors {
		privateKeyBytes, err := base58.Decode(vector.PrivateKeyBytesBase58)
		if nil != err {
			t.Fatalf("Did not expect an error but actually got one: (%T) %s", err, err)
		}
		privateKey, err := ecdh.P256().NewPrivateKey(privateKeyBytes)
		if nil != err {
			t.Fatalf("Did not expect an error but actually got one: (%T) %s", err, err)
		}

		key, err := didkey.FromECDH(privateKey.PublicKey())
		if nil != err {
			t.Errorf("For %s, did not expect an error but actually got one: (%T) %s", vector.PublicDidKey, err, err)
			continue
		}
		if vector.PublicDidKey != key.DIDKey() {
			t.Errorf("Expected %s but actually got %s.", vector.PublicDidKey, key.DIDKey())
		}

		parsed, err := didkey.Parse(vector.PublicDidKey)
		if nil != err {
			t.Errorf("For %s, did not expect an error but actually got one: (%T) %s", vector.PublicDidKey, err, err)
			continue
		}
		if !parsed.Equal(key) || !bytes.Equal(privateKey.PublicKey().Bytes(), parsed.Uncompressed()) {
			t.Errorf("For %s, the parsed key is not the derived key.", vector.PublicDidKey)
		}
		if didkey.KeyTypeP256 != parsed.Type() || "ES256" != parsed.JWTAlg() {
			t.Errorf("For %s, unexpected type %q / alg %q.", vector.PublicDidKey, parsed.Type(), parsed.JWTAlg())
		}
	}
}

// secp256k1PublicKey derives the uncompressed public key for a secp256k1 private key —
// with plain affine double-and-add, independent of the package's code.
func secp256k1PublicKey(privateKey []byte) []byte {
	p, _ := new(big.Int).SetString("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f", 16)
	gx, _ := new(big.Int).SetString("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", 16)
	gy, _ := new(big.Int).SetString("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8", 16)

	mod := func(n *big.Int) *big.Int { return n.Mod(n, p) }
	inverse := func(n *big.Int) *big.Int { return new(big.Int).ModInverse(n, p) }

	// add returns a+b (nil is the point at infinity).
	add := func(ax, ay, bx, by *big.Int) (*big.Int, *big.Int) {
		if nil == ax {
			return bx, by
		}
		if nil == bx {
			return ax, ay
		}
		var slope *big.Int
		if 0 == ax.Cmp(bx) {
			if 0 != ay.Cmp(by) || 0 == ay.Sign() {
				return nil, nil
			}
			// (3x²) / (2y)
			slope = mod(new(big.Int).Mul(mod(new(big.Int).Mul(big.NewInt(3), new(big.Int).Mul(ax, ax))), inverse(mod(new(big.Int).Mul(big.NewInt(2), ay)))))
		} else {
			// (by−ay) / (bx−ax)
			slope = mod(new(big.Int).Mul(mod(new(big.Int).Sub(by, ay)), inverse(mod(new(big.Int).Sub(bx, ax)))))
		}
		x := mod(new(big.Int).Sub(new(big.Int).Sub(new(big.Int).Mul(slope, slope), ax), bx))
		y := mod(new(big.Int).Sub(new(big.Int).Mul(slope, new(big.Int).Sub(ax, x)), ay))
		return x, y
	}

	var k *big.Int = new(big.Int).SetBytes(privateKey)
	var rx, ry *big.Int
	var qx, qy *big.Int = gx, gy
	for index := 0; index < k.BitLen(); index++ {
		if 1 == k.Bit(index) {
			rx, ry = add(rx, ry, qx, qy)
		}
		qx, qy = add(qx, qy, qx, qy)
	}

	var result []byte = make([]byte, 65)
	result[0] = 0x04
	rx.FillBytes(result[1:33])
	ry.FillBytes(result[33:])
	return result
}

func TestInterop_K256(t *testing.T) {
	var vectors []struct {
		PrivateKeyBytesHex string `json:"privateKeyBytesHex"`
		PublicDidKey       string `json:"publicDidKey"`
	}
	loadJSON(t, "testdata/w3c_didkey_K256.json", &vectors)
	if 0 == len(vectors) {
		t.Fatal("Expected some vectors.")
	}

	for _, vector := range vectors {
		privateKey, err := hex.DecodeString(vector.PrivateKeyBytesHex)
		if nil != err {
			t.Fatalf("Did not expect an error but actually got one: (%T) %s", err, err)
		}

		parsed, err := didkey.Parse(vector.PublicDidKey)
		if nil != err {
			t.Errorf("For %s, did not expect an error but actually got one: (%T) %s", vector.PublicDidKey, err, err)
			continue
		}
		if didkey.KeyTypeSecp256k1 != parsed.Type() || "ES256K" != parsed.JWTAlg() {
			t.Errorf("For %s, unexpected type %q / alg %q.", vector.PublicDidKey, parsed.Type(), parsed.JWTAlg())
		}

		// The decompressed point is the private key's public key.
		var expected []byte = secp256k1PublicKey(privateKey)
		if !bytes.Equal(expected, parsed.Uncompressed()) {
			t.Errorf("For %s, the decompressed key is not what was expected.", vector.PublicDidKey)
			t.Logf("EXPECTED: %x", expected)
			t.Logf("ACTUAL:   %x", parsed.Uncompressed())
		}

		// Made from that public key, it gives back the same did:key.
		var compressed []byte = append([]byte{0x02 | expected[64]&1}, expected[1:33]...)
		key, err := didkey.FromCompressed(didkey.KeyTypeSecp256k1, compressed)
		if nil != err {
			t.Errorf("For %s, did not expect an error but actually got one: (%T) %s", vector.PublicDidKey, err, err)
			continue
		}
		if vector.PublicDidKey != key.DIDKey() {
			t.Errorf("Expected %s but actually got %s.", vector.PublicDidKey, key.DIDKey())
		}

		if _, err := parsed.ECDSA(); !errors.Is(err, didkey.ErrNotP256) {
			t.Errorf("Expected ErrNotP256 but actually got: %v", err)
		}
	}
}

func TestInterop_signatureFixtures(t *testing.T) {
	var fixtures []struct {
		Comment            string   `json:"comment"`
		MessageBase64      string   `json:"messageBase64"`
		Algorithm          string   `json:"algorithm"`
		PublicKeyDid       string   `json:"publicKeyDid"`
		PublicKeyMultibase string   `json:"publicKeyMultibase"`
		SignatureBase64    string   `json:"signatureBase64"`
		ValidSignature     bool     `json:"validSignature"`
		Tags               []string `json:"tags"`
	}
	loadJSON(t, "testdata/signature-fixtures.json", &fixtures)
	if 0 == len(fixtures) {
		t.Fatal("Expected some fixtures.")
	}

	var verified int
	for _, fixture := range fixtures {
		key, err := didkey.Parse(fixture.PublicKeyDid)
		if nil != err {
			t.Errorf("For %q, did not expect an error but actually got one: (%T) %s", fixture.Comment, err, err)
			continue
		}
		if fixture.Algorithm != key.JWTAlg() {
			t.Errorf("For %q, expected %s but actually got %s.", fixture.Comment, fixture.Algorithm, key.JWTAlg())
		}

		// The legacy "publicKeyMultibase" is the base58btc of the compressed point, with no multicodec.
		legacy, err := base58.Decode(strings.TrimPrefix(fixture.PublicKeyMultibase, "z"))
		if nil != err || !bytes.Equal(legacy, key.Compressed()) {
			t.Errorf("For %q, the legacy multibase is not the compressed key (error: %v).", fixture.Comment, err)
		}

		// A valid P-256 signature (r‖s, low s) verifies with the parsed key.
		if "ES256" != fixture.Algorithm || !fixture.ValidSignature {
			continue
		}
		publicKey, err := key.ECDSA()
		if nil != err {
			t.Fatalf("Did not expect an error but actually got one: (%T) %s", err, err)
		}
		message, _ := base64.RawStdEncoding.DecodeString(fixture.MessageBase64)
		signature, _ := base64.RawStdEncoding.DecodeString(fixture.SignatureBase64)
		digest := sha256.Sum256(message)
		if 64 != len(signature) || !ecdsa.Verify(publicKey, digest[:], new(big.Int).SetBytes(signature[:32]), new(big.Int).SetBytes(signature[32:])) {
			t.Errorf("For %q, expected the signature to verify.", fixture.Comment)
		}
		verified++
	}
	if 0 == verified {
		t.Error("Expected to verify at least one signature.")
	}
}

func TestConversions(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if nil != err {
		t.Fatalf("Did not expect an error but actually got one: (%T) %s", err, err)
	}

	key, err := didkey.FromECDSA(&privateKey.PublicKey)
	if nil != err {
		t.Fatalf("Did not expect an error but actually got one: (%T) %s", err, err)
	}
	if !strings.HasPrefix(key.DIDKey(), "did:key:zDna") || !strings.HasPrefix(key.Multikey(), "zDna") || key.String() != key.DIDKey() {
		t.Errorf("Unexpected did:key %s / Multikey %s.", key.DIDKey(), key.Multikey())
	}

	publicKey, err := key.ECDSA()
	if nil != err || !publicKey.Equal(&privateKey.PublicKey) {
		t.Errorf("Expected the same *ecdsa.PublicKey back (error: %v).", err)
	}

	ecdhKey, err := key.ECDH()
	if nil != err {
		t.Fatalf("Did not expect an error but actually got one: (%T) %s", err, err)
	}
	again, err := didkey.FromECDH(ecdhKey)
	if nil != err || !again.Equal(key) {
		t.Errorf("Expected the same key back (error: %v).", err)
	}

	parsed, err := didkey.ParseMultikey(key.Multikey())
	if nil != err || !parsed.Equal(key) {
		t.Errorf("Expected the Multikey to round-trip (error: %v).", err)
	}

	// The returned bytes are copies.
	var compressed []byte = key.Compressed()
	compressed[1] ^= 0xff
	if bytes.Equal(compressed, key.Compressed()) {
		t.Error("Expected Compressed to return a copy.")
	}

	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if nil != err {
		t.Fatalf("Did not expect an error but actually got one: (%T) %s", err, err)
	}
	if _, err := didkey.FromECDSA(&p384.PublicKey); !errors.Is(err, didkey.ErrNotP256) {
		t.Errorf("Expected ErrNotP256 but actually got: %v", err)
	}
	x25519, err := ecdh.X25519().GenerateKey(rand.Reader)
	if nil != err {
		t.Fatalf("Did not expect an error but actually got one: (%T) %s", err, err)
	}
	if _, err := didkey.FromECDH(x25519.PublicKey()); !errors.Is(err, didkey.ErrNotP256) {
		t.Errorf("Expected ErrNotP256 but actually got: %v", err)
	}
	if _, err := didkey.FromECDSA(nil); !errors.Is(err, didkey.ErrNilKey) {
		t.Errorf("Expected ErrNilKey but actually got: %v", err)
	}

	var zero didkey.PublicKey
	if "" != zero.DIDKey() || "" != zero.JWTAlg() {
		t.Error("Expected the zero value to have no did:key.")
	}
}

func TestParse_errors(t *testing.T) {
	const valid = "did:key:zDnaeTiq1PdzvZXUaMdezchcMJQpBdH2VN4pgrrEhMCCbmwSb"

	key, err := didkey.Parse(valid)
	if nil != err {
		t.Fatalf("Did not expect an error but actually got one: (%T) %s", err, err)
	}
	var compressed []byte = key.Compressed()

	multikey := func(prefix []byte, rest []byte) string {
		return "did:key:z" + base58.Encode(append(append([]byte(nil), prefix...), rest...))
	}

	// An x whose x³ − 3x + b is not a square mod p — so no point has it. (Found by trying x = 0, 1, 2, ….)
	var notOnCurve []byte
	for x := int64(0); nil == notOnCurve; x++ {
		var candidate []byte = append([]byte{0x02}, new(big.Int).SetInt64(x).FillBytes(make([]byte, 32))...)
		if nil == unmarshalCompressedP256(candidate) {
			notOnCurve = candidate
		}
	}

	var p256P []byte = elliptic.P256().Params().P.FillBytes(make([]byte, 32))

	secp256k1PInt, _ := new(big.Int).SetString("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f", 16)
	var secp256k1P []byte = secp256k1PInt.FillBytes(make([]byte, 32))
	var secp256k1PPlus1 []byte = new(big.Int).Add(secp256k1PInt, big.NewInt(1)).FillBytes(make([]byte, 32))

	tests := []struct {
		Name     string
		Value    string
		Expected error
	}{
		{Name: "empty", Value: "", Expected: didkey.ErrBadDIDKey},
		{Name: "no did:key: prefix", Value: strings.TrimPrefix(valid, "did:key:"), Expected: didkey.ErrBadDIDKey},
		{Name: "another DID method", Value: "did:plc:zDnaeTiq1PdzvZXUaMdezchcMJQpBdH2VN4pgrrEhMCCbmwSb", Expected: didkey.ErrBadDIDKey},
		{Name: "another multibase", Value: "did:key:fDnae", Expected: didkey.ErrBadDIDKey},
		{Name: "bad base58", Value: "did:key:zDnae0OIl", Expected: didkey.ErrBadBase58},
		{Name: "ed25519", Value: "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK", Expected: didkey.ErrUnsupportedKeyType},
		{Name: "uncompressed P-256", Value: multikey([]byte{0x80, 0x24}, key.Uncompressed()), Expected: didkey.ErrBadKeyLength},
		{Name: "short", Value: multikey([]byte{0x80, 0x24}, compressed[:32]), Expected: didkey.ErrBadKeyLength},
		{Name: "bad point prefix", Value: multikey([]byte{0x80, 0x24}, append([]byte{0x05}, compressed[1:]...)), Expected: didkey.ErrNotOnCurve},
		{Name: "not on the curve", Value: multikey([]byte{0x80, 0x24}, notOnCurve), Expected: didkey.ErrNotOnCurve},
		{Name: "x = p", Value: multikey([]byte{0x80, 0x24}, append([]byte{0x02}, p256P...)), Expected: didkey.ErrNotOnCurve},
		// For secp256k1, x = 0 has no point: 0³ + 7 = 7 is not a square mod p. (Checked independently, with Python and Euler's criterion.)
		{Name: "secp256k1, x = 0", Value: multikey([]byte{0xe7, 0x01}, append([]byte{0x02}, make([]byte, 32)...)), Expected: didkey.ErrNotOnCurve},
		{Name: "secp256k1, x = p", Value: multikey([]byte{0xe7, 0x01}, append([]byte{0x02}, secp256k1P...)), Expected: didkey.ErrNotOnCurve},
		// x = p + 1 would be x = 1 (mod p), which has a point — so a missing x < p check would accept it.
		{Name: "secp256k1, x = p + 1", Value: multikey([]byte{0xe7, 0x01}, append([]byte{0x02}, secp256k1PPlus1...)), Expected: didkey.ErrNotOnCurve},
	}

	for _, test := range tests {
		if _, err := didkey.Parse(test.Value); !errors.Is(err, test.Expected) {
			t.Errorf("For %q, expected %v but actually got: %v", test.Name, test.Expected, err)
		}
	}

	if _, err := didkey.ParseMultikey("Dnae"); !errors.Is(err, didkey.ErrBadMultibase) {
		t.Errorf("Expected ErrBadMultibase but actually got: %v", err)
	}
	if _, err := didkey.FromCompressed("ed25519", compressed); !errors.Is(err, didkey.ErrUnsupportedKeyType) {
		t.Errorf("Expected ErrUnsupportedKeyType but actually got: %v", err)
	}
}

func unmarshalCompressedP256(compressed []byte) []byte {
	x, _ := elliptic.UnmarshalCompressed(elliptic.P256(), compressed)
	if nil == x {
		return nil
	}
	return compressed
}
