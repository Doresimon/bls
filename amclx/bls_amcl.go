package amclx

import (
	"github.com/milagro-crypto/amcl/version3/go/amcl"
	"github.com/milagro-crypto/amcl/version3/go/amcl/FP256BN"
)

var order = FP256BN.NewBIGints(FP256BN.CURVE_Order)
var g2 = FP256BN.ECP2_generator()

// KeyGenerate() (*FP256BN.BIG, *FP256BN.ECP2)
// Key Generation. For a particular user, pick random x <-$- Zp,
// and compute v = g2^x. The user’s
// public key is v <--- G2. The user’s secret key is x <--- Zp.
func KeyGenerate() (*FP256BN.BIG, *FP256BN.ECP2) {
	sk := FP256BN.Randomnum(order, amcl.NewRAND())

	// pk := new(FP256BN.ECP2)
	pk := FP256BN.NewECP2()
	pk.Copy(g2)
	pk.Mul(sk)

	return sk, pk
}
