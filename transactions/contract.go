package transactions

import (
	_ "embed"
	"fmt"
)

// CONTRACT TRANSACTIONS

//go:embed contract.cdc
var contract []byte

var CallEmptyContractFunctionTransaction = func(
	loopLength uint64,
) *SimpleTransaction {
	return simpleTransactionWithLoop(
		"call empty contract function",
		"CEC",
		loopLength,
		`TestContract.empty()`,
	)
}

var EmitEventTransaction = func(
	loopLength uint64,
) *SimpleTransaction {
	return simpleTransactionWithLoop(
		"emit event",
		"CEE",
		loopLength,
		`TestContract.emitEvent()`,
	)
}

var MintNFTTransaction = func(
	loopLength uint64,
) *SimpleTransaction {
	return simpleTransactionWithLoop(
		"mint NFT",
		"CMNFT",
		loopLength,
		`TestContract.mintNFT()`,
	)
}

var EmitEventWithStringTransaction = func(
	dictLen uint64,
) *SimpleTransaction {
	return NewSimpleTransaction(
		"emit event with string",
		"CEES",
	).
		SetPrepareBlock(fmt.Sprintf(`
			let dict: {String: String} = %s
			TestContract.emitDictEvent(dict)
		`, stringDictOfLen(dictLen, 50)))
}
