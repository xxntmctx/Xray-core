package shadowsocks_2022

import (
	"encoding/base64"
	"encoding/hex"
	"strings"

	"lukechampine.com/blake3"
)

const (
	ContextSessionSubKey  = "shadowsocks 2022 session subkey"
	ContextIdentitySubKey = "shadowsocks 2022 identity subkey"
)

// ParseKey decodes a base64 or raw PSK key string and validates its length
func ParseKey(key string, keyLength int) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		raw = []byte(key)
	}
	if len(raw) == keyLength {
		return raw, nil
	}

	// Case 1: Handle keys where raw binary bytes were converted to a UTF-8 string before Base64 encoding.
	// (Common when binary bytes > 127 are treated as Latin-1 chars and converted to 2-byte UTF-8, expanding 32 bytes to 48 bytes)
	if len(raw) > keyLength {
		runes := []rune(string(raw))
		if len(runes) == keyLength {
			res := make([]byte, keyLength)
			valid := true
			for i, r := range runes {
				if r > 0xFF {
					valid = false
					break
				}
				res[i] = byte(r)
			}
			if valid {
				return res, nil
			}
		}
	}

	// Case 2: Handle hex-encoded keys (e.g. 32 hex chars for 16-byte key, 64 hex chars for 32-byte key)
	if hexBytes, err := hex.DecodeString(key); err == nil && len(hexBytes) == keyLength {
		return hexBytes, nil
	}

	return nil, ErrBadKey
}

func ParsePSKList(password string, keyLength int) ([][]byte, error) {
	parts := strings.Split(password, ":")
	pskList := make([][]byte, len(parts))
	for i, part := range parts {
		norm, err := ParseKey(part, keyLength)
		if err != nil {
			return nil, err
		}
		pskList[i] = norm
	}
	return pskList, nil
}

func deriveSubKey(ctx string, psk, salt []byte, keyLength int) []byte {
	var keyMaterial [64]byte
	kmLen := len(psk) + len(salt)
	copy(keyMaterial[:], psk)
	copy(keyMaterial[len(psk):], salt)
	out := make([]byte, keyLength)
	blake3.DeriveKey(out, ctx, keyMaterial[:kmLen])
	return out
}

func DeriveSessionSubKey(psk, salt []byte, keyLength int) []byte {
	return deriveSubKey(ContextSessionSubKey, psk, salt, keyLength)
}

func DeriveIdentitySubKey(psk, salt []byte, keyLength int) []byte {
	return deriveSubKey(ContextIdentitySubKey, psk, salt, keyLength)
}

func DeriveUserPSKHash(userPSK []byte) [AESBlockSize]byte {
	h := blake3.Sum512(userPSK)
	var out [AESBlockSize]byte
	copy(out[:], h[:AESBlockSize])
	return out
}

func DecryptEIH(method *CipherMethod, key, salt, eih []byte) ([AESBlockSize]byte, error) {
	identitySubkey := DeriveIdentitySubKey(key, salt, method.KeySaltLength)
	block, err := method.NewBlock(identitySubkey)
	if err != nil {
		return [AESBlockSize]byte{}, err
	}
	var decryptedHash [AESBlockSize]byte
	block.Decrypt(decryptedHash[:], eih)
	return decryptedHash, nil
}
