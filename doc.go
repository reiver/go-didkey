/*
Package didkey implements did:key and Multikey public keys — as used by ATProto — for the Go programming language.

ATProto uses two kinds of key: P-256 (JWT alg "ES256") and secp256k1 (JWT alg "ES256K").
A key is written as a did:key, or (in a DID document's "publicKeyMultibase") as a Multikey — which is a did:key without its "did:key:" prefix:

	did:key:zDnaeTiq1PdzvZXUaMdezchcMJQpBdH2VN4pgrrEhMCCbmwSb    (P-256 — always starts "zDna")
	did:key:zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme    (secp256k1 — always starts "zQ3s")

After the "z" (multibase base58btc) is the base58btc encoding of:

	• the multicodec code, as an unsigned varint — p256-pub (0x80 0x24) or secp256k1-pub (0xe7 0x01),
	• the compressed public key — 0x02 or 0x03 (the parity of y), then x — 33 bytes.

Parsing checks that the key is a valid point on its curve. Uncompressed keys, and other key types (ex: Ed25519), are rejected.

The specs are here:

https://atproto.com/specs/cryptography

https://w3c-ccg.github.io/did-method-key/

# P-256 and secp256k1

P-256 keys convert to and from Go's *ecdsa.PublicKey (ex: to verify ES256 signatures) and *ecdh.PublicKey (ex: for HPKE).

Go's standard library has no secp256k1. So secp256k1 keys can be parsed, checked, decompressed, and written — but not converted to a Go key type.
(Their points are available with [PublicKey.Compressed] and [PublicKey.Uncompressed].)

# Example

	key, err := didkey.Parse("did:key:zDnaeTiq1PdzvZXUaMdezchcMJQpBdH2VN4pgrrEhMCCbmwSb")
	if nil != err {
		return err
	}

	publicKey, err := key.ECDSA() // *ecdsa.PublicKey

	// The other way:
	key, err = didkey.FromECDSA(&privateKey.PublicKey)
	fmt.Println(key.DIDKey())   // did:key:zDna…
	fmt.Println(key.Multikey()) // zDna…
*/
package didkey
