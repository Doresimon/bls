package dedis

import (
	"testing"

	"github.com/dedis/kyber/pairing/bn256"
	"github.com/dedis/kyber/sign/bls"
	"github.com/dedis/kyber/util/random"
	"github.com/stretchr/testify/require"
)

func TestBLS(t *testing.T) {
	msg := []byte("Hello Boneh-Lynn-Shacham")
	suite := bn256.NewSuite()
	private, public := bls.NewKeyPair(suite, random.New())
	sig, err := bls.Sign(suite, private, msg)
	require.Nil(t, err)
	err = bls.Verify(suite, public, msg, sig)
	require.Nil(t, err)
}

func TestBLSFailSig(t *testing.T) {
	msg := []byte("Hello Boneh-Lynn-Shacham")
	suite := bn256.NewSuite()
	private, public := bls.NewKeyPair(suite, random.New())
	sig, err := bls.Sign(suite, private, msg)
	require.Nil(t, err)
	sig[0] ^= 0x01
	if bls.Verify(suite, public, msg, sig) == nil {
		t.Fatal("bls: verification succeeded unexpectedly")
	}
}

func TestBLSFailKey(t *testing.T) {
	msg := []byte("Hello Boneh-Lynn-Shacham")
	suite := bn256.NewSuite()
	private, _ := bls.NewKeyPair(suite, random.New())
	sig, err := bls.Sign(suite, private, msg)
	require.Nil(t, err)
	_, public := bls.NewKeyPair(suite, random.New())
	if bls.Verify(suite, public, msg, sig) == nil {
		t.Fatal("bls: verification succeeded unexpectedly")
	}
}
