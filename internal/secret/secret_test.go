package secret

import "testing"

func TestEncryptRoundTrip(t *testing.T) {
	const plain = "s3cr3t-smtp-pass"
	enc, err := Encrypt(plain)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if enc == plain {
		t.Fatal("ciphertext equals plaintext")
	}
	got, err := Decrypt(enc)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if got != plain {
		t.Fatalf("roundtrip = %q, want %q", got, plain)
	}
}

func TestEncryptNonceVaries(t *testing.T) {
	a, _ := Encrypt("x")
	b, _ := Encrypt("x")
	if a == b {
		t.Fatal("same plaintext produced identical ciphertext (nonce not random)")
	}
}

func TestDecryptRejectsGarbage(t *testing.T) {
	if _, err := Decrypt("not-base64!!"); err == nil {
		t.Fatal("expected error on invalid base64")
	}
	if _, err := Decrypt("YWJj"); err == nil { // valid base64, too short / bad
		t.Fatal("expected error on corrupt ciphertext")
	}
}
