package musig_test

import (
	"testing"

	"github.com/btcsuite/btcd/btcec"
	"github.com/tnakagawa/musig"
)

func TestOk(t *testing.T) {
	// Alice
	// private/public keys
	x1, X1 := musig.KeyGen()
	// random value
	r1, R1 := musig.KeyGen()

	// Bob
	// private/public keys
	x2, X2 := musig.KeyGen()
	// random value
	r2, R2 := musig.KeyGen()

	// L is a multiset of public keys.
	var L []*btcec.PublicKey
	L = append(L, X1)
	L = append(L, X2)
	t.Log("Public keys")
	for i, l := range L {
		t.Logf("L%d:%x", i, l.SerializeCompressed())
	}

	// R is a part of signature.
	R := musig.AddPubs(R1, R2)

	// message
	t.Log("Message")
	m := []byte("message")
	t.Logf("m:%x", m)

	//Signing
	// Alice signs.
	s1 := musig.Sign(L, R, m, x1, r1)
	// Bob signs.
	s2 := musig.Sign(L, R, m, x2, r2)
	// s is a part of signature.
	s := musig.AddSigs(s1, s2)
	// signature
	t.Log("Signature")
	t.Logf("R:%x", R.SerializeCompressed())
	t.Logf("s:%v", s)

	// Verification
	v := musig.Ver(L, R, m, s)
	t.Logf("Result:%v", v)

	if v != 1 {
		t.Error("Fail")
	}
}

func TestNg(t *testing.T) {
	// Alice
	// private/public keys
	x1, X1 := musig.KeyGen()
	// random value
	r1, R1 := musig.KeyGen()

	// Bob
	// private/public keys
	x2, X2 := musig.KeyGen()
	// random value
	r2, R2 := musig.KeyGen()

	// L is a multiset of public keys.
	var L []*btcec.PublicKey
	L = append(L, X1)
	L = append(L, X2)
	t.Log("Public keys")
	for i, l := range L {
		t.Logf("L%d:%x", i, l.SerializeCompressed())
	}

	// R is a part of signature.
	R := musig.AddPubs(R1, R2)

	// message
	t.Log("Message1")
	m1 := []byte("message1")
	t.Logf("m1:%x", m1)

	//Signing
	// Alice signs.
	s1 := musig.Sign(L, R, m1, x1, r1)
	// Bob signs.
	s2 := musig.Sign(L, R, m1, x2, r2)
	// s is a part of signature.
	s := musig.AddSigs(s1, s2)
	// signature
	t.Log("Signature")
	t.Logf("R:%x", R.SerializeCompressed())
	t.Logf("s:%v", s)

	// message
	t.Log("Message2")
	m2 := []byte("message2")
	t.Logf("m2:%x", m2)

	// Verification
	v := musig.Ver(L, R, m2, s)
	t.Logf("Result:%v", v)

	if v != 0 {
		t.Error("Fail")
	}
}
