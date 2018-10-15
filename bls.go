package main

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
	"reflect"

	"golang.org/x/crypto/bn256"
)

// KeyGenerate () (*big.Int, *bn256.G2)
// Key Generation. For a particular user, pick random x R Zp, and compute v g2x. The user’s
// public key is v 2 G2. The user’s secret key is x 2 Zp.
func KeyGenerate() (*big.Int, *bn256.G2) {
	sk, pk, _ := bn256.RandomG2(rand.Reader)
	return sk, pk
}

// Sign (sk *big.Int, msg string) *bn256.G1
// Signing. For a particular user, given the secret key x and a message M 2 f0; 1g∗, compute
// h H(M), where h 2 G1, and σ hx. The signature is σ 2 G1.
func Sign(sk *big.Int, msg string) *bn256.G1 {
	h := hashToG1(msg)
	sig := new(bn256.G1).ScalarMult(h, sk)
	return sig
}

// Verify (pk *bn256.G2, msg string, sig *bn256.G1) bool
// Verification. Given user’s public key v, a message M, and a signature σ, compute h H(M);
// accept if e(σ; g2) = e(h; v) holds.
func Verify(pk *bn256.G2, msg string, sig *bn256.G1) bool {
	g2 := new(bn256.G2).ScalarBaseMult(big.NewInt(1))
	h := hashToG1(msg)
	lp := bn256.Pair(sig, g2)
	rp := bn256.Pair(h, pk)
	ok := reflect.DeepEqual(lp.Marshal(), rp.Marshal())
	return ok
}

// hashToG1 (msg string) *bn256.G1
func hashToG1(msg string) *bn256.G1 {
	// hash to point of G1
	H := sha256.New()
	H.Write([]byte(msg))
	tmp := new(big.Int).SetBytes(H.Sum(nil))
	return new(bn256.G1).ScalarBaseMult(tmp)
}

func main() {
	// key generation
	sk, pk := KeyGenerate()

	// signing
	msg := "hello world"
	sig := Sign(sk, msg)

	// verifying
	ok := Verify(pk, msg, sig)
	// fmt.Printf("[lp] %v\n", lp.Marshal())
	// fmt.Printf("[rp] %v\n", rp.Marshal())
	fmt.Printf("[ok] %v\n", ok)

	// end
}
