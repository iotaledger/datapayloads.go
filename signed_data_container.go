// rename to datapayloads
package datapayloads

import (
	"crypto"
	"encoding/json"
	"errors"
	"fmt"

	"golang.org/x/crypto/blake2b"

	"github.com/iotaledger/hive.go/serializer/v2"
	iotago "github.com/iotaledger/iota.go/v3"
	iotagoEd25519 "github.com/iotaledger/iota.go/v3/ed25519"
)

// TaggedDataPayloadType defines the type of the tagged data payload.
type TaggedDataPayloadType byte

const (
	// TaggedDataPayloadTypeSignedDataContainer denotes a signed data container.
	TaggedDataPayloadTypeSignedDataContainer TaggedDataPayloadType = 0
)

var (
	ErrNotASignedDataContainer = errors.New("not a signed data container")
	// ErrInvalidSignature gets returned when a signature is invalid.
	ErrInvalidSignature = errors.New("invalid signature")

	signedDataContainerSupportedSigTypes = iotago.SignatureTypeSet{iotago.SignatureEd25519: struct{}{}}

	// restrictions around signature within a signed data container.
	signedDataContainerSignatureGuard = serializer.SerializableGuard{
		ReadGuard:  iotago.SignatureReadGuard(signedDataContainerSupportedSigTypes),
		WriteGuard: iotago.SignatureWriteGuard(signedDataContainerSupportedSigTypes),
	}
)

type SignedDataContainer struct {
	// The data held by the data container.
	Data []byte
	// The signature held by the data container.
	Signature iotago.Signature
}

// NewSignedDataContainer creates a new SignedDataContainer.
func NewSignedDataContainer(signer Signer, data []byte) (*SignedDataContainer, error) {
	container := &SignedDataContainer{
		Data:      data,
		Signature: nil,
	}

	if err := container.sign(signer); err != nil {
		return nil, err
	}

	return container, nil
}

// NewSignedDataContainerFromBytes creates a new SignedDataContainer from data.
// ATTENTION: It does not verify the signature yet. This can be done via "VerifySignature".
func NewSignedDataContainerFromBytes(data []byte) (*SignedDataContainer, error) {
	// quick check without memory allocation
	if data[0] != byte(TaggedDataPayloadTypeSignedDataContainer) {
		return nil, ErrNotASignedDataContainer
	}

	container := &SignedDataContainer{}
	if _, err := container.Deserialize(data, serializer.DeSeriModePerformValidation, nil); err != nil {
		return nil, err
	}

	return container, nil
}

// Sign produces the signature with the given signer function and updates the Signature field of the SignedDataContainer.
func (s *SignedDataContainer) sign(signer Signer) error {
	essence, err := s.Essence()
	if err != nil {
		return fmt.Errorf("unable to compute essence for signed data container: %w", err)
	}

	signature, err := signer.Sign(essence)
	if err != nil {
		return fmt.Errorf("unable to produce signed data container signature: %w", err)
	}

	s.Signature = signature
	return nil
}

// VerifySignature verifies that the signature within the container is valid.
func (s *SignedDataContainer) VerifySignature() error {
	if s.Signature == nil {
		return fmt.Errorf("%w: no signature given", ErrInvalidSignature)
	}

	essence, err := s.Essence()
	if err != nil {
		return fmt.Errorf("unable to compute signed data container essence for signature verification: %w", err)
	}

	switch s.Signature.(type) {
	case *iotago.Ed25519Signature:
		// guaranteed by deserialization
		edSig := s.Signature.(*iotago.Ed25519Signature)

		if ok := iotagoEd25519.Verify(edSig.PublicKey[:], essence[:], edSig.Signature[:]); !ok {
			return fmt.Errorf("%w: %s", ErrInvalidSignature, edSig)
		}

		return nil
	default:
		return fmt.Errorf("%w: type %T", ErrUnknownPrivateKeyType, s.Signature)
	}
}

func (s *SignedDataContainer) PublicKey() (crypto.PublicKey, error) {
	if s.Signature == nil {
		return nil, fmt.Errorf("%w: no signature given", ErrInvalidSignature)
	}

	switch s.Signature.(type) {
	case *iotago.Ed25519Signature:
		return s.Signature.(*iotago.Ed25519Signature).PublicKey, nil
	default:
		return nil, fmt.Errorf("%w: type %T", iotago.ErrUnknownSignatureType, s.Signature)
	}
}

// Essence returns the essence bytes (the bytes to be signed) of the data container.
func (s *SignedDataContainer) Essence() ([]byte, error) {
	essenceBytes, err := serializer.NewSerializer().
		WriteByte(byte(TaggedDataPayloadTypeSignedDataContainer), func(err error) error {
			return fmt.Errorf("unable to serialize signed data container type essence: %w", err)
		}).
		WriteVariableByteSlice(s.Data, serializer.SeriLengthPrefixTypeAsUint16, func(err error) error {
			return fmt.Errorf("unable to serialize signed data container data for essence: %w", err)
		}, 0, 0).
		Serialize()
	if err != nil {
		return nil, err
	}
	essenceHash := blake2b.Sum256(essenceBytes)
	return essenceHash[:], nil
}

func (s *SignedDataContainer) Deserialize(data []byte, deSeriMode serializer.DeSerializationMode, deSeriCtx interface{}) (int, error) {
	return serializer.NewDeserializer(data).
		CheckTypePrefix(uint32(TaggedDataPayloadTypeSignedDataContainer), serializer.TypeDenotationByte, func(err error) error {
			return fmt.Errorf("unable to deserialize signed data container type: %w", err)
		}).
		ReadVariableByteSlice(&s.Data, serializer.SeriLengthPrefixTypeAsUint16, func(err error) error {
			return fmt.Errorf("unable to deserialize signed data container data: %w", err)
		}, 0, 0).
		ReadObject(&s.Signature, deSeriMode, deSeriCtx, serializer.TypeDenotationByte, signedDataContainerSignatureGuard.ReadGuard, func(err error) error {
			return fmt.Errorf("unable to deserialize signed data container signature: %w", err)
		}).
		ConsumedAll(func(leftOver int, err error) error {
			return fmt.Errorf("unable to deserialize signed data container: %w: %d bytes are still available", err, leftOver)
		}).
		Done()
}

func (s *SignedDataContainer) Serialize(deSeriMode serializer.DeSerializationMode, deSeriCtx interface{}) ([]byte, error) {
	return serializer.NewSerializer().
		WriteByte(byte(TaggedDataPayloadTypeSignedDataContainer), func(err error) error {
			return fmt.Errorf("unable to serialize signed data container type: %w", err)
		}).
		WriteVariableByteSlice(s.Data, serializer.SeriLengthPrefixTypeAsUint16, func(err error) error {
			return fmt.Errorf("unable to serialize signed data container data: %w", err)
		}, 0, 0).
		WriteObject(s.Signature, deSeriMode, deSeriCtx, signedDataContainerSignatureGuard.WriteGuard, func(err error) error {
			return fmt.Errorf("unable to serialize signed data container signature: %w", err)
		}).
		Serialize()
}

func (s *SignedDataContainer) MarshalJSON() ([]byte, error) {
	jSignedDataContainer := &jsonSignedDataContainer{}
	jSignedDataContainer.Type = int(TaggedDataPayloadTypeSignedDataContainer)
	jSignedDataContainer.Data = s.Data

	jsonSig, err := s.Signature.MarshalJSON()
	if err != nil {
		return nil, err
	}
	rawJsonSig := json.RawMessage(jsonSig)
	jSignedDataContainer.Signature = &rawJsonSig

	return json.Marshal(jSignedDataContainer)
}

func (s *SignedDataContainer) UnmarshalJSON(bytes []byte) error {
	jSignedDataContainer := &jsonSignedDataContainer{}
	if err := json.Unmarshal(bytes, jSignedDataContainer); err != nil {
		return err
	}
	seri, err := jSignedDataContainer.ToSerializable()
	if err != nil {
		return err
	}
	*s = *seri.(*SignedDataContainer)
	return nil
}

// jsonSignedDataContainer defines the json representation of a SignedDataContainer.
type jsonSignedDataContainer struct {
	Type      int              `json:"type"`
	Data      []byte           `json:"data"`
	Signature *json.RawMessage `json:"signature"`
}

func (j *jsonSignedDataContainer) ToSerializable() (serializer.Serializable, error) {
	var err error

	payload := &SignedDataContainer{}
	payload.Data = j.Data
	signature, err := iotago.SignatureFromJSONRawMsg(j.Signature)
	if err != nil {
		return nil, err
	}
	payload.Signature = signature

	return payload, nil
}
