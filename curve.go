package didkey

import (
	"crypto/elliptic"
	"math/big"
)

// secp256k1: y² = x³ + 7 (mod p).
var secp256k1P, _ = new(big.Int).SetString("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f", 16)

// decompress returns the uncompressed point (0x04 ‖ x ‖ y, 65 bytes) for a compressed point (0x02 or 0x03 ‖ x, 33 bytes),
// or nil if it is not a valid point on the curve.
func decompress(keyType KeyType, compressed []byte) []byte {
	if compressedSize != len(compressed) || (0x02 != compressed[0] && 0x03 != compressed[0]) {
		return nil
	}

	switch keyType {
	case KeyTypeP256:
		x, y := elliptic.UnmarshalCompressed(elliptic.P256(), compressed)
		if nil == x {
			return nil
		}
		return uncompressedBytes(x, y)

	case KeyTypeSecp256k1:
		var p *big.Int = secp256k1P

		var x *big.Int = new(big.Int).SetBytes(compressed[1:])
		if 0 <= x.Cmp(p) {
			return nil
		}

		// y² = x³ + 7
		var y2 *big.Int = new(big.Int).Exp(x, big.NewInt(3), p)
		y2.Add(y2, big.NewInt(7))
		y2.Mod(y2, p)

		// p ≡ 3 (mod 4), so a square root of y² (if there is one) is (y²)^((p+1)/4).
		var y *big.Int = new(big.Int).Exp(y2, new(big.Int).Rsh(new(big.Int).Add(p, big.NewInt(1)), 2), p)
		if 0 != new(big.Int).Exp(y, big.NewInt(2), p).Cmp(y2) {
			return nil
		}

		if byte(y.Bit(0)) != compressed[0]&1 {
			y.Sub(p, y)
		}
		return uncompressedBytes(x, y)

	default:
		return nil
	}
}

func uncompressedBytes(x *big.Int, y *big.Int) []byte {
	var p []byte = make([]byte, uncompressedSize)
	p[0] = 0x04
	x.FillBytes(p[1:33])
	y.FillBytes(p[33:])
	return p
}
