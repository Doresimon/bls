package main

import (
	"fmt"

	"github.com/dedis/kyber/pairing/bn256"
	"github.com/dedis/kyber/sign/bls"
	"github.com/dedis/kyber/util/random"
)

func main() {
	msg := []byte("Hello Boneh-Lynn-Shacham")
	suite := bn256.NewSuite()
	private, public := bls.NewKeyPair(suite, random.New())
	sig, _ := bls.Sign(suite, private, msg)

	_ = bls.Verify(suite, public, msg, sig)

	b_priv, _ := private.MarshalBinary()
	b_pub, _ := public.MarshalBinary()
	b_sig := sig

	fmt.Printf("byte private: %v \n", b_priv)
	fmt.Printf("byte public: %v \n", b_pub)
	fmt.Printf("byte sig: %v \n", b_sig)

	fmt.Printf("size private: %v \n", len(b_priv)*8)
	fmt.Printf("size public: %v \n", len(b_pub)*8)
	fmt.Printf("size sig: %v \n", len(b_sig)*8)

}
