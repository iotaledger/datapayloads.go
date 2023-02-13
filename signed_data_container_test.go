//#nosec G404

package datapayloads

import (
	"crypto"
	"encoding/json"
	"errors"
	"testing"

	"github.com/iotaledger/iota.go/v3/tpkg"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/iotaledger/hive.go/serializer/v2"
)

type deSerializeTest struct {
	name      string
	source    serializer.Serializable
	target    serializer.Serializable
	seriErr   error
	deSeriErr error
}

func (test *deSerializeTest) deSerialize(t *testing.T) {
	data, err := test.source.Serialize(serializer.DeSeriModePerformValidation, tpkg.TestProtoParas)
	if test.seriErr != nil {
		require.Error(t, err, test.seriErr)
		return
	}
	assert.NoError(t, err)
	if src, ok := test.source.(serializer.SerializableWithSize); ok {
		assert.Equal(t, len(data), src.Size())
	}

	bytesRead, err := test.target.Deserialize(data, serializer.DeSeriModePerformValidation, tpkg.TestProtoParas)
	if test.deSeriErr != nil {
		require.Error(t, err, test.deSeriErr)
		return
	}
	assert.NoError(t, err)
	require.Len(t, data, bytesRead)
	assert.EqualValues(t, test.source, test.target)
}

// RandSignedDataContainer returns a random signed data container.
func RandSignedDataContainer(dataLength int) *SignedDataContainer {
	signedDataContainer := &SignedDataContainer{
		Data:      tpkg.RandBytes(dataLength),
		Signature: tpkg.RandEd25519Signature(),
	}

	return signedDataContainer
}

func TestSignedDataContainer_DeSerialize(t *testing.T) {
	tests := []deSerializeTest{
		{
			name:   "ok",
			source: RandSignedDataContainer(1000),
			target: &SignedDataContainer{},
		},
		{
			name:   "empty-data",
			source: RandSignedDataContainer(0),
			target: &SignedDataContainer{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, tt.deSerialize)
	}
}

func TestSignedDataContainer_MarshalUnmarshalJSON(t *testing.T) {
	container := RandSignedDataContainer(500)
	pubKeyContainer, err := container.PublicKey()
	require.NoError(t, err)

	containerJSON, err := json.Marshal(container)
	require.NoError(t, err)

	result := &SignedDataContainer{}
	require.NoError(t, json.Unmarshal(containerJSON, result))

	require.EqualValues(t, container, result)

	pubKeyResult, err := result.PublicKey()
	require.NoError(t, err)

	require.EqualValues(t, pubKeyContainer, pubKeyResult)
}

func TestSignedDataContainerSigning(t *testing.T) {
	type test struct {
		name            string
		container       *SignedDataContainer
		signer          Signer
		prvKey          crypto.PrivateKey
		verificationErr error
	}

	tests := []test{
		func() test {
			prvKey := tpkg.RandEd25519PrivateKey()
			signer := NewInMemorySigner(prvKey)

			signedDataContainer, err := NewSignedDataContainer(signer, tpkg.RandBytes(100))
			require.NoError(t, err)

			return test{
				name:            "ok",
				container:       signedDataContainer,
				signer:          signer,
				prvKey:          prvKey,
				verificationErr: nil,
			}
		}(),
		func() test {
			prvKey := tpkg.RandEd25519PrivateKey()
			signer := NewInMemorySigner(prvKey)

			signedDataContainer, err := NewSignedDataContainer(signer, tpkg.RandBytes(100))
			require.NoError(t, err)

			// modify the payload after signing
			signedDataContainer.Data = signedDataContainer.Data[1:]

			return test{
				name:            "err - invalid signature",
				container:       signedDataContainer,
				signer:          signer,
				prvKey:          prvKey,
				verificationErr: ErrInvalidSignature,
			}
		}(),
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.container.VerifySignature()
			if tt.verificationErr != nil {
				assert.True(t, errors.Is(err, tt.verificationErr))
				return
			}
			assert.NoError(t, err)
		})
	}
}
