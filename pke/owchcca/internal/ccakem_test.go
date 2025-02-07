package internal

import (
	"crypto/rand"
	"fmt"
	"testing"
)

func TestNewKeyFromGaussian(t *testing.T) {
	randSource := rand.Reader
	_, sk, _ := NewKeyFromGaussian(randSource)

	fmt.Print("row: ", len(sk.Z_b), " col: ", len(sk.Z_b[0]))
	fmt.Print("b is:", sk.b)
}
