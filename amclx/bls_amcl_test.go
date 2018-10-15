package amclx

import (
	"testing"
)

func Benchmark_KeyGenerate(b *testing.B) {
	for i := 0; i < b.N; i++ {
		KeyGenerate()
	}
}
