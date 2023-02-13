package datapayloads

import (
	"crypto"
	"crypto/ed25519"
	"errors"
	"fmt"

	iotago "github.com/iotaledger/iota.go/v3"
)

var (
	// ErrUnknownPrivateKeyType gets returned for unknown private key types.
	ErrUnknownPrivateKeyType = errors.New("unknown private key type")
)

// Signer produces signatures for messages which get verified against a given public key.
type Signer interface {
	// Sign produces the signature for the given message.
	Sign(msg []byte) (signature iotago.Signature, err error)
}

// InMemorySigner implements Signer by holding keys simply in-memory.
type InMemorySigner struct {
	privateKey crypto.PrivateKey
}

// NewInMemoryAddressSigner creates a new NewInMemorySigner holding the given private key.
func NewInMemorySigner(privateKey crypto.PrivateKey) Signer {
	return &InMemorySigner{
		privateKey: privateKey,
	}
}

func (s *InMemorySigner) Sign(msg []byte) (signature iotago.Signature, err error) {
	switch prvKey := s.privateKey.(type) {
	case ed25519.PrivateKey:
		ed25519Sig := &iotago.Ed25519Signature{}
		copy(ed25519Sig.Signature[:], ed25519.Sign(prvKey, msg))
		copy(ed25519Sig.PublicKey[:], prvKey.Public().(ed25519.PublicKey))

		return ed25519Sig, nil
	default:
		return nil, fmt.Errorf("%w: type %T", ErrUnknownPrivateKeyType, prvKey)
	}
}
