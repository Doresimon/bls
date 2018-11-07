package cryptox

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
	"reflect"

	"golang.org/x/crypto/bn256"
)

const (
	// PublicKeySize is the size, in bytes, of public keys as used in this package.
	PublicKeySize = 32
	// PrivateKeySize is the size, in bytes, of private keys as used in this package.
	PrivateKeySize = 64
	// SignatureSize is the size, in bytes, of signatures generated and verified by this package.
	SignatureSize = 64
	// SeedSize is the size, in bytes, of private key seeds. These are the private key representations used by RFC 8032.
	SeedSize = 32
)

// PublicKey is the type of Ed25519 public keys.
type PublicKey []byte

// PrivateKey is the type of Ed25519 private keys. It implements crypto.Signer.
type PrivateKey []byte

// Public returns the PublicKey corresponding to priv.
func (priv PrivateKey) Public() crypto.PublicKey {
	publicKey := make([]byte, PublicKeySize)
	copy(publicKey, priv[32:])
	return PublicKey(publicKey)
}

//
func (priv PrivateKey) Sign(message []byte) (signature []byte, err error) {
	sk := big.NewInt(0).SetBytes(priv)
	sig := Sign(sk, string(message))

	return sig.Marshal(), nil
}

// Verify reports whether sig is a valid signature of message by publicKey. It
// will panic if len(publicKey) is not PublicKeySize.
func (pub PublicKey) Verify(message, sigBytes []byte) bool {
	sig, _ := (*bn256.G1).Unmarshal(new(bn256.G1).ScalarBaseMult(big.NewInt(1)), sigBytes)
	pk, _ := (*bn256.G2).Unmarshal(new(bn256.G2).ScalarBaseMult(big.NewInt(1)), pub)

	return Verify(pk, string(message), sig)
}

// KeyGenerate () (*big.Int, *bn256.G2)
// Key Generation. For a particular user, pick random x <-$- Zp,
// and compute v = g2^x. The user’s
// public key is v <--- G2. The user’s secret key is x <--- Zp.
func KeyGenerate() (*big.Int, *bn256.G2, PrivateKey, PublicKey) {
	sk, pk, _ := bn256.RandomG2(rand.Reader)
	skBytes := sk.Bytes()
	pkBytes := pk.Marshal()
	return sk, pk, PrivateKey(skBytes), PublicKey(pkBytes)
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
