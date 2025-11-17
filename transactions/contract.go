package transactions

import (
	_ "embed"
	"fmt"
)

// CONTRACT TRANSACTIONS
// see contract.cdc for the contract code

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

var EmitEventWithStringTransaction = func(
	dictLen uint64,
) *SimpleTransaction {
	return NewSimpleTransaction(
		fmt.Sprintf(`
			let dict: {String: String} = %s
			TestContract.emitDictEvent(dict)
		`, stringDictOfLen(dictLen, 50)),
	)
}
