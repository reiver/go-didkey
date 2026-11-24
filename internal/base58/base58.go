package base58

import (
	"errors"
	"math/big"
)

// alphabet is the Bitcoin base58 alphabet ("base58btc").
const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

var ErrBadCharacter = errors.New("base58: bad character")

var radix = big.NewInt(58)

// Encode returns the base58btc encoding of 'p'. (Each leading zero byte becomes a leading "1".)
func Encode(p []byte) string {
	var zeros int
	for zeros < len(p) && 0 == p[zeros] {
		zeros++
	}

	var n *big.Int = new(big.Int).SetBytes(p)
	var mod *big.Int = new(big.Int)

	var reversed []byte
	for 0 < n.Sign() {
		n.DivMod(n, radix, mod)
		reversed = append(reversed, alphabet[mod.Int64()])
	}

	var result []byte = make([]byte, 0, zeros+len(reversed))
	for range zeros {
		result = append(result, '1')
	}
	for index := len(reversed) - 1; 0 <= index; index-- {
		result = append(result, reversed[index])
	}
	return string(result)
}

// Decode returns the bytes whose base58btc encoding is 's'.
func Decode(s string) ([]byte, error) {
	var zeros int
	for zeros < len(s) && '1' == s[zeros] {
		zeros++
	}

	var n *big.Int = new(big.Int)
	for index := 0; index < len(s); index++ {
		var digit int = indexOf(s[index])
		if digit < 0 {
			return nil, ErrBadCharacter
		}
		n.Mul(n, radix)
		n.Add(n, big.NewInt(int64(digit)))
	}

	var result []byte = make([]byte, zeros)
	return append(result, n.Bytes()...), nil
}

func indexOf(c byte) int {
	for index := 0; index < len(alphabet); index++ {
		if c == alphabet[index] {
			return index
		}
	}
	return -1
}
