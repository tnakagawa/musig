package musig

import (
	"crypto/rand"
	"crypto/sha256"
	"math/big"

	"github.com/btcsuite/btcd/btcec"
)

// KeyGen returns a private/public key pair.
func KeyGen() (*btcec.PrivateKey, *btcec.PublicKey) {
	x, _ := rand.Int(rand.Reader, btcec.S256().N)
	return btcec.PrivKeyFromBytes(btcec.S256(), x.Bytes())
}

// Sign returns a signature.
// L = {X1, ... , Xn} is the multiset of all public keys.
// R is sum all random points. R = R1 + ... + Rn
// m is message.
// x is private key. Xi = xG, X is public key.
// r is random value. Ri = rG.
func Sign(L []*btcec.PublicKey, R *btcec.PublicKey, m []byte, x, r *btcec.PrivateKey) *big.Int {
	var a *big.Int
	Xt := new(btcec.PublicKey)
	// X~ = a_0*X_0 + ... + a_n*X_n
	for i, Xi := range L {
		// a_i = H_agg(L,X_i)
		ai := Hagg(L, Xi)
		if i == 0 {
			Xt.X, Xt.Y = btcec.S256().ScalarMult(Xi.X, Xi.Y, ai.Bytes())
		} else {
			Xix, Xiy := btcec.S256().ScalarMult(Xi.X, Xi.Y, ai.Bytes())
			Xt.X, Xt.Y = btcec.S256().Add(Xt.X, Xt.Y, Xix, Xiy)
		}
		if a == nil && Xi.IsEqual(x.PubKey()) {
			a = ai
		}
	}
	// c = H_sig(H~,R,m)
	c := Hsig(Xt, R, m)
	// 	s_i = r_i + c*a_i*x_i mod p
	s := new(big.Int).Mod(new(big.Int).Add(r.D, new(big.Int).Mul(new(big.Int).Mul(c, a), x.D)), btcec.S256().N)
	return s
}

// Ver returns 1 if the signature is valid and 0 otherwise.
// L = {X1, ... , Xn} is the multiset of all public keys.
// m is message.
// σ = (R,s)
// R is sum all random points. R = R1 + ... + Rn
// s is signature.
func Ver(L []*btcec.PublicKey, m []byte, R *btcec.PublicKey, s *big.Int) int {
	Xt := new(btcec.PublicKey)
	// X~ = a_0*X_0 + ... + a_n*X_n
	for i, Xi := range L {
		// a_i = H_agg(L,X_i)
		ai := Hagg(L, Xi)
		if i == 0 {
			Xt.X, Xt.Y = btcec.S256().ScalarMult(Xi.X, Xi.Y, ai.Bytes())
		} else {
			Xix, Xiy := btcec.S256().ScalarMult(Xi.X, Xi.Y, ai.Bytes())
			Xt.X, Xt.Y = btcec.S256().Add(Xt.X, Xt.Y, Xix, Xiy)
		}
	}
	// c = H_sig(H~,R,m)
	c := Hsig(Xt, R, m)
	cXt := new(btcec.PublicKey)
	// cX~ = c * X~
	cXt.X, cXt.Y = btcec.S256().ScalarMult(Xt.X, Xt.Y, c.Bytes())
	RXc := new(btcec.PublicKey)
	// R + cX~
	RXc.X, RXc.Y = btcec.S256().Add(R.X, R.Y, cXt.X, cXt.Y)
	// sG = s*G
	sG := new(btcec.PublicKey)
	sG.X, sG.Y = btcec.S256().ScalarBaseMult(s.Bytes())
	// sG = R + cX~
	if sG.IsEqual(RXc) {
		return 1
	}
	return 0
}

// Hagg returns hash value.
func Hagg(L []*btcec.PublicKey, R *btcec.PublicKey) *big.Int {
	s := sha256.New()
	for _, Xi := range L {
		s.Write(Xi.SerializeCompressed())
	}
	s.Write(R.SerializeCompressed())
	hash := s.Sum(nil)
	h := big.NewInt(0)
	h.SetBytes(hash)
	return h
}

// Hsig returns hash value.
func Hsig(X, R *btcec.PublicKey, m []byte) *big.Int {
	s := sha256.New()
	s.Write(X.SerializeCompressed())
	s.Write(R.SerializeCompressed())
	s.Write(m)
	hash := s.Sum(nil)
	h := big.NewInt(0)
	h.SetBytes(hash)
	return h
}

// Hcom returns hash value.
func Hcom(R *btcec.PublicKey) []byte {
	s := sha256.New()
	s.Write(R.SerializeCompressed())
	hash := s.Sum(nil)
	return hash
}

// AddPubs returns sum public key.
func AddPubs(pubs ...*btcec.PublicKey) *btcec.PublicKey {
	P := new(btcec.PublicKey)
	for i, pub := range pubs {
		if i == 0 {
			P.X, P.Y = pub.X, pub.Y
		} else {
			P.X, P.Y = btcec.S256().Add(P.X, P.Y, pub.X, pub.Y)
		}
	}
	return P
}

// AddSigs returns sum signature.
func AddSigs(sigs ...*big.Int) *big.Int {
	S := big.NewInt(0)
	for _, sig := range sigs {
		S = new(big.Int).Add(S, sig)
	}
	return S
}
