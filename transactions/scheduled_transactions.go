package transactions

import (
	"fmt"
	"strings"
)

const scheduleTemplate = `
	if !signer.storage.check<@TestContract.Handler>(from: TestContract.HandlerStoragePath) {
		let handler <- TestContract.createHandler()

		signer.storage.save(<-handler, to: TestContract.HandlerStoragePath)
		signer.capabilities.storage.issue<auth(FlowTransactionScheduler.Execute) &{FlowTransactionScheduler.TransactionHandler}>(TestContract.HandlerStoragePath)
	}

	let handlerCap = signer.capabilities.storage
						.getControllers(forPath: TestContract.HandlerStoragePath)[0]
						.capability as! Capability<auth(FlowTransactionScheduler.Execute) &{FlowTransactionScheduler.TransactionHandler}>

	let vault = signer.storage.borrow<auth(FungibleToken.Withdraw) &FlowToken.Vault>(from: /storage/flowTokenVault)
		?? panic("Could not borrow FlowToken vault")

	%s

	let scheduledTransaction <- FlowTransactionScheduler.schedule(
		handlerCap: handlerCap,
		data: data,
		timestamp: timestamp,
		priority: priority,
		executionEffort: effort,
		fees: <-fees
	)
	destroy scheduledTransaction
`

var ScheduledTransactionAndExecuteTransaction = func(loopLength uint64) *SimpleTransaction {
	return simpleTransactionWithLoop(
		loopLength,
		fmt.Sprintf(scheduleTemplate, `
				let fees <- vault.withdraw(amount: 0.003) as! @FlowToken.Vault
				let timestamp = getCurrentBlock().timestamp + 120.0 // 2 minutes in future
				let effort: UInt64 = 100
				let priority = FlowTransactionScheduler.Priority.High
				let data: UInt64 = 0
			`),
	)
}

var ScheduledTransactionAndExecuteWithLargeDataTransaction = func(loopLength uint64, dataSize uint64) *SimpleTransaction {
	return simpleTransactionWithLoop(
		loopLength,
		fmt.Sprintf(scheduleTemplate, fmt.Sprintf(`
			let fees <- vault.withdraw(amount: 0.11) as! @FlowToken.Vault
			let timestamp = getCurrentBlock().timestamp + 120.0 // 2 minutes in future
			let effort: UInt64 = 100
			let priority = FlowTransactionScheduler.Priority.High
			let data = "%s"
		`, strings.Repeat("A", int(100*dataSize)))), // inject dataSize KB of data
	)
}

var ScheduledTransactionAndExecuteWithLargeArrayTransaction = func(loopLength uint64, arraySize uint64) *SimpleTransaction {
	return simpleTransactionWithLoop(
		loopLength,
		fmt.Sprintf(scheduleTemplate, fmt.Sprintf(`
			let largeArray: [Int] = []
			while largeArray.length < %d {
				largeArray.append(1)

			let fees <- vault.withdraw(amount: 0.01) as! @FlowToken.Vault
			let timestamp = getCurrentBlock().timestamp + 120.0 // 2 minutes in future
			let effort: UInt64 = 100
			let priority = FlowTransactionScheduler.Priority.High
			let data = largeArray
		`, arraySize)),
	)
}
