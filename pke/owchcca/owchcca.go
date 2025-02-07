package owchcca

import (
	"io"

	"github.com/cloudflare/circl/pke/owchcca/internal"
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

type PublicKey = internal.PublicKey

type PrivateKey = internal.PrivateKey

// GenerateKey generates a public/private key pair using entropy from rand.
// Paper use the seed from Setup with par := random(Z_q, n x m)
func GenerateKey(rand io.Reader) (*PublicKey, *PrivateKey, error) {
	pk, sk, err := internal.NewKeyFromGaussian(rand)
	if err != nil {
		return nil, nil, err
	}
	return pk, sk, nil
}
