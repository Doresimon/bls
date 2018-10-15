package bls

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

// Aggregate (sigs []*bn256.G1) *bn256.G1
// Aggregation. For the aggregating subset of users U ⊆ U, assign to each user an index i, ranging
// from 1 to k = jUj. Each user ui 2 U provides a signature σi 2 G1 on a message Mi 2 f0; 1g∗
// of his choice. The messages Mi must all be distinct. Compute σ Qk i=1 σi. The aggregate
// signature is σ 2 G1.
func Aggregate(sigs []*bn256.G1) *bn256.G1 {
	if len(sigs) <= 1 {
		fmt.Printf("invalid input.")
		return nil
	}

	asig := new(bn256.G1).ScalarBaseMult(big.NewInt(0))
	for _, sig := range sigs {
		asig.Add(asig, sig)
	}

	return asig
}

// AVerify (asig *bn256.G1, msgs []string, pks []*bn256.G2) bool
// Aggregate Verification. We are given an aggregate signature σ <-- G1 for an aggregating subset
// of users U, indexed as before, and are given the original messages Mi <-- {1, 0}∗ and public
// keys vi <-- G2 for all users ui <-- U. To verify the aggregate signature σ,
// 1. ensure that the messages Mi are all distinct, and reject otherwise; and
// 2. compute hi = H(Mi) for 1 ≤ i ≤ k = |U|, and accept if e(σ, g2) = MullAll(e(hi, vi)) holds.
func AVerify(asig *bn256.G1, msgs []string, pks []*bn256.G2) bool {
	if len(msgs) != len(pks) {
		fmt.Printf("messages and public keys have different quantity.")
		return false
	}
	g2 := new(bn256.G2).ScalarBaseMult(big.NewInt(1))

	hs := make([]*bn256.G1, len(msgs), len(msgs))

	for i, msg := range msgs {
		hs[i] = hashToG1(msg)
	}

	lp := bn256.Pair(asig, g2)

	rp := bn256.Pair(hs[0], pks[0])

	for i := 1; i < len(pks); i++ {
		rp.Add(rp, bn256.Pair(hs[i], pks[i]))
	}
	ok := reflect.DeepEqual(lp.Marshal(), rp.Marshal())
	return ok
}

// hashToG1 (msg string) *bn256.G1
// naive version
func hashToG1(msg string) *bn256.G1 {
	// hash to point of G1
	H := sha256.New()
	H.Write([]byte(msg))
	tmp := new(big.Int).SetBytes(H.Sum(nil))
	return new(bn256.G1).ScalarBaseMult(tmp)
}
