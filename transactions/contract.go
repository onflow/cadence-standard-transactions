package transactions

import (
	_ "embed"
	"fmt"
)

// CONTRACT TRANSACTIONS

//go:embed contract.cdc
var TestContractCode []byte

var CallEmptyContractFunctionTransaction = func(
	loopLength uint64,
) *SimpleTransaction {
	return simpleTransactionWithLoop(
		loopLength,
		`TestContract.empty()`,
	)
}

var EmitEventTransaction = func(
	loopLength uint64,
) *SimpleTransaction {
	return simpleTransactionWithLoop(
		loopLength,
		`TestContract.emitEvent()`,
	)
}

var MintNFTTransaction = func(
	loopLength uint64,
) *SimpleTransaction {
	return simpleTransactionWithLoop(
		loopLength,
		`TestContract.mintNFT()`,
	)
}

// ArrayDestroyManyTransaction destroys a small @[Item] array per iteration.
// Profile: high DestroyArrayValue; zero AtreeArrayGet, EVMGasUsage.
var ArrayDestroyManyTransaction = func(
	loopLength uint64,
) *SimpleTransaction {
	return simpleTransactionWithLoop(
		loopLength,
		`let arr: @[TestContract.Item] <- [
			<- TestContract.mintItem(),
			<- TestContract.mintItem(),
			<- TestContract.mintItem(),
			<- TestContract.mintItem()
		]
		destroy arr`,
	)
}

// MintItemAndStoreTransaction mints an Item into the contract's array (no destroy).
// Profile: high GenerateUUID; zero DestroyCompositeValue, DestroyArrayValue.
var MintItemAndStoreTransaction = func(
	loopLength uint64,
) *SimpleTransaction {
	return simpleTransactionWithLoop(
		loopLength,
		`TestContract.mintItemAndStore()`,
	)
}

// MintDestroyItemTransaction mints and immediately destroys one Item.
// Profile: high GenerateUUID + DestroyCompositeValue (1:1); zero DestroyArrayValue.
var MintDestroyItemTransaction = func(
	loopLength uint64,
) *SimpleTransaction {
	return simpleTransactionWithLoop(
		loopLength,
		`let item <- TestContract.mintItem()
		destroy item`,
	)
}

// MakeStructTransaction instantiates an empty struct per iteration.
// Profile: high CreateCompositeValue; zero GenerateUUID — every other CCV template
// creates resources, fusing the two.
var MakeStructTransaction = func(
	loopLength uint64,
) *SimpleTransaction {
	return simpleTransactionWithLoop(
		loopLength,
		`let s = TestContract.Empty()`,
	)
}

var EmitEventWithStringTransaction = func(
	dictLen uint64,
) *SimpleTransaction {
	return NewSimpleTransaction(
		fmt.Sprintf(`
			let dict: {String: String} = %s
			TestContract.emitDictEvent(dict)
		`, StringDictOfLen(dictLen, 50)),
	)
}
