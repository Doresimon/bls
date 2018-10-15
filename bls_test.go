package bls

import (
	"math/big"
	"strconv"
	"testing"

	"golang.org/x/crypto/bn256"
)

func Test_BLS_Short_Signature_Scheme(t *testing.T) {

	// key generation
	sk, pk := KeyGenerate()

	// signing
	msg := "hello world"
	sig := Sign(sk, msg)

	// verifying
	ok := Verify(pk, msg, sig)

	if !ok {
		t.Error("verification failed.")
	}

	// end
}
func Test_BLS_Aggregate_Signature_Scheme(t *testing.T) {
	N := 64
	sks := make([]*big.Int, N, N)
	pks := make([]*bn256.G2, N, N)
	msgs := make([]string, N, N)
	sigs := make([]*bn256.G1, N, N)

	for i := 0; i < N; i++ {
		sks[i], pks[i] = KeyGenerate()
		msgs[i] = "hello world" + strconv.Itoa(i)
		sigs[i] = Sign(sks[i], msgs[i])
	}

	asig := Aggregate(sigs)

	ok := AVerify(asig, msgs, pks)

	if !ok {
		t.Error("aggregate signature verification failed.")
	}

	// end
}

func Benchmark_KeyGenerate(b *testing.B) {
	for i := 0; i < b.N; i++ {
		KeyGenerate()
	}
}
func Benchmark_Sign(b *testing.B) {
	sk, _ := KeyGenerate()
	msg := "hello world"

	for i := 0; i < b.N; i++ {
		Sign(sk, msg)
	}
}
func Benchmark_Verify(b *testing.B) {
	sk, pk := KeyGenerate()
	msg := "hello world"
	sig := Sign(sk, msg)

	for i := 0; i < b.N; i++ {
		Verify(pk, msg, sig)
	}
}
