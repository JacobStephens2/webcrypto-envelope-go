package envelope

import (
	"strings"
	"testing"
)

func TestPasswordDerivedEnvelope(t *testing.T) {
	fast := &DeriveOptions{Iterations: 10_000} // keep round-trip tests quick

	t.Run("round-trips", func(t *testing.T) {
		key, err := DeriveKey("correct horse battery staple", RandomSalt(), fast)
		if err != nil {
			t.Fatal(err)
		}
		env, err := Encrypt("hello, health data", key)
		if err != nil {
			t.Fatal(err)
		}
		got, err := Decrypt(env, key)
		if err != nil {
			t.Fatal(err)
		}
		if got != "hello, health data" {
			t.Errorf("got %q", got)
		}
	})

	t.Run("fails with the wrong password", func(t *testing.T) {
		salt := RandomSalt()
		rightKey, _ := DeriveKey("right", salt, fast)
		wrongKey, _ := DeriveKey("wrong", salt, fast)
		env, err := Encrypt("secret", rightKey)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Decrypt(env, wrongKey); err == nil {
			t.Error("decrypt with wrong password succeeded")
		}
	})

	t.Run("uses a fresh IV per call", func(t *testing.T) {
		key, _ := DeriveKey("pw", RandomSalt(), fast)
		a, err := Encrypt("x", key)
		if err != nil {
			t.Fatal(err)
		}
		b, err := Encrypt("x", key)
		if err != nil {
			t.Fatal(err)
		}
		if a == b {
			t.Error("ciphertext identical for identical input")
		}
	})

	t.Run("honors a custom iteration count", func(t *testing.T) {
		key, err := DeriveKey("pw", RandomSalt(), &DeriveOptions{Iterations: 50_000})
		if err != nil {
			t.Fatal(err)
		}
		env, _ := Encrypt("ok", key)
		if got, err := Decrypt(env, key); err != nil || got != "ok" {
			t.Errorf("got %q, err %v", got, err)
		}
	})

	t.Run("rejects an invalid base64 salt", func(t *testing.T) {
		if _, err := DeriveKey("pw", "not base64!!!", fast); err == nil {
			t.Error("invalid salt accepted")
		}
	})
}

func TestSealOpen(t *testing.T) {
	t.Run("round-trips with the returned key", func(t *testing.T) {
		key, env, err := Seal("observations json")
		if err != nil {
			t.Fatal(err)
		}
		got, err := Open(env, key)
		if err != nil {
			t.Fatal(err)
		}
		if got != "observations json" {
			t.Errorf("got %q", got)
		}
	})

	t.Run("cannot be opened with a different key", func(t *testing.T) {
		_, env, err := Seal("observations json")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Open(env, RandomKey()); err == nil {
			t.Error("opened with the wrong key")
		}
	})

	t.Run("rejects a tampered envelope", func(t *testing.T) {
		key, env, err := Seal("data")
		if err != nil {
			t.Fatal(err)
		}
		parts := strings.Split(env, ":")
		parts[2] = RandomKey() // corrupt the ciphertext
		if _, err := Open(strings.Join(parts, ":"), key); err == nil {
			t.Error("tampered envelope opened")
		}
	})
}

func TestEnvelopeFormat(t *testing.T) {
	t.Run("is iv:tag:ciphertext (three base64 parts)", func(t *testing.T) {
		_, env, err := Seal("x")
		if err != nil {
			t.Fatal(err)
		}
		if got := len(strings.Split(env, ":")); got != 3 {
			t.Errorf("envelope has %d parts, want 3", got)
		}
	})

	t.Run("rejects malformed input without panicking", func(t *testing.T) {
		for _, env := range []string{
			"not-an-envelope",
			"a:b",
			"a:b:c:d",
			"!!!:!!!:!!!",
			"AAAA:AAAA:AAAA", // valid base64, wrong IV length
			"",
		} {
			if _, err := Open(env, RandomKey()); err == nil {
				t.Errorf("malformed envelope %q opened", env)
			}
		}
	})

	t.Run("rejects an invalid base64 key", func(t *testing.T) {
		_, env, _ := Seal("x")
		if _, err := Open(env, "not base64!!!"); err == nil {
			t.Error("invalid key accepted")
		}
	})

	t.Run("produces a UTF-8-safe round-trip", func(t *testing.T) {
		key, env, err := Seal("emoji 🔐 and accénts")
		if err != nil {
			t.Fatal(err)
		}
		if got, _ := Open(env, key); got != "emoji 🔐 and accénts" {
			t.Errorf("got %q", got)
		}
	})
}

// Fixtures sealed by the TypeScript twin (webcrypto-envelope, Node 22,
// Web Crypto). Opening them here is the wire-compatibility proof in the
// TS→Go direction; the TS test suite carries Go-sealed fixtures for the
// reverse.
func TestOpensTypeScriptSealedEnvelopes(t *testing.T) {
	t.Run("password vault, default iterations", func(t *testing.T) {
		key, err := DeriveKey("correct horse battery staple", "c2FsdC1mb3ItaW50ZXJvcA==", nil)
		if err != nil {
			t.Fatal(err)
		}
		got, err := Decrypt("ktEZMtWOW6eVi1m0:8GHkrf9CDjB6nLaBMGvA6g==:RnwWkKgJKNkF44TTaOGwxfHJ", key)
		if err != nil {
			t.Fatal(err)
		}
		if got != "hello, health data" {
			t.Errorf("got %q", got)
		}
	})

	t.Run("password vault, custom iterations", func(t *testing.T) {
		key, err := DeriveKey("pw", "c2FsdC1mb3ItaW50ZXJvcA==", &DeriveOptions{Iterations: 100_000})
		if err != nil {
			t.Fatal(err)
		}
		got, err := Decrypt("q5AYIFEjeago2zdB:v1OFHoJ6JhCbDST39dTFcg==:WM/59xPUqVxepJFOBN6FUiQ=", key)
		if err != nil {
			t.Fatal(err)
		}
		if got != "observations json" {
			t.Errorf("got %q", got)
		}
	})

	t.Run("sealed share with multi-byte UTF-8", func(t *testing.T) {
		got, err := Open(
			"3uY6iJJQlhem7Ggk:BY3dqhkfi9VcoxAcOttBhw==:Re7TpBxyWOpxDpy0Wkq+zldIV2pjdVs=",
			"timsRUiOnjX0xI3IFVqMbOMgPUBO5T+OwemfwhBhemA=",
		)
		if err != nil {
			t.Fatal(err)
		}
		if got != "emoji 🔐 and accénts" {
			t.Errorf("got %q", got)
		}
	})
}
