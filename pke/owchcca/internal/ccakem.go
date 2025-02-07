package internal

import (
	cryptoRand "crypto/rand"
	"io"
	"math/big"

	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/utils/sampling"
)

const (
	// Size of seed for NewKeyFromSeed
	KeySeedSize = 32

	// Size of seed for EncapsulateTo.
	EncapsulationSeedSize = 32

	// Size of the established shared key.
	SharedKeySize = 32

	// Size of the encapsulated shared key.
	CiphertextSize = 32

	// Size of a packed public key.
	PublicKeySize = 32

	// Size of a packed private key.
	PrivateKeySize = 32
)

const (
	K        = 2
	N        = 16
	M        = 32
	Alpha    = 2
	Alpha_   = 2
	Eta1     = 3
	DU       = 10
	DV       = 4
	SeedSize = 32
	Lambda   = 32
	// Q change q to string
	Q = 12289
)

type (
	Vec []*big.Int
	Mat []Vec
)

type PrivateKey struct {
	Poly_Z_b ring.Poly
	Z_b      []*big.Int
	b        bool
}

type PublicKey struct {
	U0 []*big.Int
	U1 []*big.Int
}

func NewKeyFromGaussian(rand io.Reader) (*PublicKey, *PrivateKey, error) {
	var pk PublicKey
	var sk PrivateKey

	// generate single bit b
	b := make([]byte, 1)
	if _, err := io.ReadFull(rand, b); err != nil {
		return nil, nil, err
	}
	sk.b = b[0] == 1

	seed := make([]byte, SeedSize)
	if _, err := io.ReadFull(rand, seed); err != nil {
		return nil, nil, err
	}

	samplingPRNG := sampling.PRNG(rand)
	// Z_b <- Gaussian Z_q, alpha with m x lambda
	// sk.Z_b, moduli = SampleD(M, Alpha_, samplingPRNG)
	moduli := testParameters.pi
	newRing, err := ring.NewRing(M, moduli)
	if err != nil {
		panic(err)
	}
	p := newRing.Modulus()
	pFloat, _ := p.Float64()
	d := ring.DiscreteGaussian{Sigma: Alpha_, Bound: pFloat}
	sampler, err := ring.NewSampler(samplingPRNG, newRing, d, false)
	if err != nil {
		panic(err)
	}
	// with m row
	sk.Poly_Z_b = sampler.ReadNew()
	sk.Z_b = make(Vec, M)
	for i := range sk.Z_b {
		sk.Z_b[i] = new(big.Int)
	}
	newRing.PolyToBigint(sk.Poly_Z_b, 1, sk.Z_b)

	uniform_sampler := ring.NewUniformSampler(samplingPRNG, newRing)
	// Generate matrix A in Z_q n x m in random, size of A will be n x m x lambda
	// in the following, i will simplify the process
	// 1. use each row of A as a polynomial, multiply with Z_b to get a Vector
	// 2. for each row, calculate the sum mod q to get a Vector(Az_b)
	polyA := make([]ring.Poly, N)
	vecPolyAz := make([]ring.Poly, N)
	for i := range N {
		polyA[i] = uniform_sampler.ReadNew()
		newRing.MulCoeffsBarrett(polyA[i], sk.Poly_Z_b, vecPolyAz[i])
	}
	vecAz := make(Vec, N)
	for i := range N {
		coeffs := make([]*big.Int, M)
		for j := range M {
			coeffs[j] = new(big.Int)
		}
		newRing.PolyToBigint(vecPolyAz[i], 1, coeffs)
		// calculate sum of each row mod q
		vecAz[i] = new(big.Int)
		for j := range M {
			vecAz[i].Add(vecAz[i], coeffs[j])
			vecAz[i].Mod(vecAz[i], p)
		}
	}
	vecZq := make(Vec, N)
	for i := range N {
		vecZq[i], err = cryptoRand.Int(rand, p)
		if err != nil {
			return nil, nil, err
		}
	}
	if sk.b {
		pk.U0 = vecAz
		pk.U1 = vecZq
	} else {
		pk.U0 = vecZq
		pk.U1 = vecAz
	}
	return &pk, &sk, nil
}
