package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"time"

	"github.com/iotaledger/datapayloads.go"
	"github.com/iotaledger/hive.go/serializer/v2"
	iotago "github.com/iotaledger/iota.go/v3"
	"github.com/iotaledger/iota.go/v3/builder"
	"github.com/iotaledger/iota.go/v3/nodeclient"
)

func main() {
	// WARNING: this creates a random seed to generate a private key for the example.
	// You need to replace that part with your own private key, and you need to take care about securing it yourself.
	var randomSeed [ed25519.SeedSize]byte
	readBytes, err := rand.Read(randomSeed[:])
	if err != nil {
		panic(fmt.Sprintf("could not read required bytes from secure RNG: %s", err))
	}
	if readBytes != ed25519.SeedSize {
		panic(fmt.Sprintf("could not read %d required bytes from secure RNG", ed25519.SeedSize))
	}
	prvKey := ed25519.NewKeyFromSeed(randomSeed[:])
	pubKey := prvKey.Public().(ed25519.PublicKey)
	println(fmt.Sprintf("PublicKey: %s", iotago.EncodeHex(pubKey[:])))

	// create a node client.
	nodeClient := nodeclient.New("https://api.shimmer.network")

	// fetch the latest node info to get the current protocol parameters.
	ctxInfo, cancelInfo := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelInfo()

	nodeInfo, err := nodeClient.Info(ctxInfo)
	if err != nil {
		panic(fmt.Sprintf("unable to fetch node info: %s", err))
	}

	// create an in-memory signer.
	signer := datapayloads.NewInMemorySigner(prvKey)

	// create a signed data container with your own data.
	// the data is signed during creation of the container.
	signedDataContainer, err := datapayloads.NewSignedDataContainer(signer, []byte("my singed message"))
	if err != nil {
		panic(fmt.Sprintf("signing data failed: %s", err))
	}

	// serialize the data container to binary format.
	signedData, err := signedDataContainer.Serialize(serializer.DeSeriModePerformValidation, nil)
	if err != nil {
		panic(fmt.Sprintf("serializing data failed: %s", err))
	}

	// put the serialized bytes in a tagged data payload with the tag of your choice.
	taggedDataPayload := &iotago.TaggedData{
		Tag:  []byte("my tag"),
		Data: signedData,
	}

	ctxTips, cancelTips := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelTips()

	// create an iota block that contains the tagged data payload.
	// in this step, we query the node for tips and do the Proof of Work.
	block, err := builder.NewBlockBuilder().
		Payload(taggedDataPayload).
		Tips(ctxTips, nodeClient).
		ProofOfWork(context.Background(), &nodeInfo.Protocol, float64(nodeInfo.Protocol.MinPoWScore)).
		Build()
	if err != nil {
		panic(fmt.Sprintf("creating block failed: %s", err))
	}

	// submit the newly created block to the tangle.
	ctxSend, cancelSend := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelSend()

	blockID, err := nodeClient.SubmitBlock(ctxSend, block, &nodeInfo.Protocol)
	if err != nil {
		panic(fmt.Sprintf("submitting block failed: %s", err))
	}

	println(fmt.Sprintf("Successfully submitted block with signed data payload.\nSee https://explorer.iota.org/shimmer/block/%s", blockID.ToHex()))
}
