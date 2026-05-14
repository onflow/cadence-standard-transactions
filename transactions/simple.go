package transactions

import (
	"encoding/hex"
	"fmt"
	"strings"

	crypto2 "github.com/onflow/crypto"
)

// for end users, there is a bunch of constructor functions which each represent a simple template

// SIMPLE TRANSACTIONS

var EmptyLoopTransaction = func(loopLength uint64) *SimpleTransaction {
	return simpleTransactionWithLoop(
		loopLength,
		"",
	)
}

// ArraySubscriptReadSetupScript seeds /storage/calibrationArr with a 32-element
// [UInt64]. Run once per account before ArraySubscriptReadTransaction.
const ArraySubscriptReadSetupScript = `
	if signer.storage.borrow<&[UInt64]>(from: /storage/calibrationArr) == nil {
		var arr: [UInt64] = []
		var k: UInt64 = 0
		while k < 32 {
			arr.append(k)
			k = k + 1
		}
		signer.storage.save<[UInt64]>(arr, to: /storage/calibrationArr)
	}
`

// ArraySubscriptReadTransaction subscript-reads element 0 of a pre-stored [UInt64].
// Profile: high AtreeArrayGet; zero DestroyArrayValue, EVMGasUsage.
// Requires ArraySubscriptReadSetupScript.
var ArraySubscriptReadTransaction = func(loopLength uint64) *SimpleTransaction {
	return simpleTransactionWithLoop(
		loopLength,
		`let arrRef = signer.storage.borrow<&[UInt64]>(from: /storage/calibrationArr)!
				let _ = arrRef[0]`,
	)
}

// EmptyLoopInt64Transaction is the Int64-counter sibling of EmptyLoopTransaction.
// Profile: high Statement / zero WordSliceOperation (Int64 doesn't meter WSO).
var EmptyLoopInt64Transaction = func(loopLength uint64) *SimpleTransaction {
	return simpleTransactionWithInt64Loop(
		loopLength,
		"",
	)
}

// BigIntAdditionChainTransaction adds a wide Int literal ~16x per iter in an Int64
// loop. Profile: low Statement / high WordSliceOperation — counterpart to
// EmptyLoopInt64Transaction.
var BigIntAdditionChainTransaction = func(loopLength uint64) *SimpleTransaction {
	// 100-digit literal → ~333 bits → ~6 big.Words on 64-bit platforms.
	const bigLiteral = "1234567890123456789012345678901234567890" +
		"1234567890123456789012345678901234567890" +
		"12345678901234567890"
	body := "let big: Int = " + bigLiteral + "\n" +
		"\t\t\t\tlet _ = big + big + big + big + big + big + big + big" +
		" + big + big + big + big + big + big + big + big"
	return simpleTransactionWithInt64Loop(loopLength, body)
}

var AssertTrueTransaction = func(loopLength uint64) *SimpleTransaction {
	return simpleTransactionWithLoop(
		loopLength,
		"assert(true)",
	)
}

var GetSignerAddressTransaction = func(loopLength uint64) *SimpleTransaction {
	return simpleTransactionWithLoop(
		loopLength,
		"signer.address",
	)
}

var GetSignerPublicAccountTransaction = func(loopLength uint64) *SimpleTransaction {
	return simpleTransactionWithLoop(
		loopLength,
		"getAccount(signer.address)",
	)
}

var GetSignerAccountBalanceTransaction = func(loopLength uint64) *SimpleTransaction {
	return simpleTransactionWithLoop(
		loopLength,
		"signer.balance",
	)
}

var GetSignerAccountAvailableBalanceTransaction = func(loopLength uint64) *SimpleTransaction {
	return simpleTransactionWithLoop(
		loopLength,
		"signer.availableBalance",
	)
}

var GetSignerAccountStorageUsedTransaction = func(loopLength uint64) *SimpleTransaction {
	return simpleTransactionWithLoop(
		loopLength,
		"signer.storage.used",
	)
}

var GetSignerAccountStorageCapacityTransaction = func(loopLength uint64) *SimpleTransaction {
	return simpleTransactionWithLoop(
		loopLength,
		"signer.storage.capacity",
	)
}

var BorrowSignerAccountFlowTokenVaultTransaction = func(loopLength uint64) *SimpleTransaction {
	return simpleTransactionWithLoop(
		loopLength,
		"let vaultRef = signer.storage.borrow<auth(FungibleToken.Withdraw) &FlowToken.Vault>(from: /storage/flowTokenVault)!",
	)
}

var BorrowSignerAccountFungibleTokenReceiverTransaction = func(loopLength uint64) *SimpleTransaction {
	return simpleTransactionWithLoop(
		loopLength,
		`
			let receiverRef = getAccount(signer.address)
				.capabilities.borrow<&{FungibleToken.Receiver}>(/public/flowTokenReceiver)!
			`,
	)
}

var TransferTokensToSelfTransaction = func(loopLength uint64) *SimpleTransaction {
	return simpleTransactionWithLoop(
		loopLength,
		`
			let vaultRef = signer.storage.borrow<auth(FungibleToken.Withdraw) &FlowToken.Vault>(from: /storage/flowTokenVault)!
			
			let receiverRef = getAccount(signer.address)
				.capabilities.borrow<&{FungibleToken.Receiver}>(/public/flowTokenReceiver)!
			receiverRef.deposit(from: <-vaultRef.withdraw(amount: 0.00001))
			`,
	)
}

var CreateNewAccountTransaction = func(loopLength uint64) *SimpleTransaction {
	return simpleTransactionWithLoop(
		loopLength,
		"let acct = Account(payer: signer)",
	)
}

var CreateNewAccountWithContractTransaction = func(loopLength uint64) *SimpleTransaction {
	return simpleTransactionWithLoop(
		loopLength,
		`
			let acct = Account(payer: signer)
			acct.contracts.add(name: "EmptyContract", code: "61636365737328616c6c2920636f6e747261637420456d707479436f6e7472616374207b7d".decodeHex())
			`,
	)
}

var DecodeHexTransaction = func(loopLength uint64) *SimpleTransaction {
	return simpleTransactionWithLoop(
		loopLength,
		`"f847b84000fb479cb398ab7e31d6f048c12ec5b5b679052589280cacde421af823f93fe927dfc3d1e371b172f97ceeac1bc235f60654184c83f4ea70dd3b7785ffb3c73802038203e8".decodeHex()`,
	)
}

// DecodeHexTinyTransaction calls "00".decodeHex() per iter. The 1-byte result goes
// through AtreeArraySingleSlabConstruction, separating string_decode_hex from
// atree_array_batch_construction (which the long-hex companion locks together).
var DecodeHexTinyTransaction = func(loopLength uint64) *SimpleTransaction {
	return simpleTransactionWithLoop(
		loopLength,
		`let _ = "00".decodeHex()`,
	)
}

// SaveLoadEmptyArrayTransaction saves an empty [Int] and immediately loads it back.
// Profile: high AllocateSlabIndex + AtreeArraySingleSlabConstruction + SetValue +
// GetValue; zero AtreeMapSingleSlabConstruction — decorrelates allocate_slab_index
// from atree_map_single_slab_construction (templates hitting either usually hit both
// via save/load on single-slab dicts).
var SaveLoadEmptyArrayTransaction = func(loopLength uint64) *SimpleTransaction {
	return simpleTransactionWithLoop(
		loopLength,
		`signer.storage.save<[Int]>([], to: /storage/ArrSLASource)
			signer.storage.load<[Int]>(from: /storage/ArrSLASource)`,
	)
}

// DictMakeTransaction creates a single-entry in-memory dict per iter (no save/copy).
// Profile: high CreateDictionaryValue + AllocateSlabIndex + DestroyDictionaryValue;
// zero AtreeMapSingleSlabConstruction and zero storage-domain map ops — pairs with
// SaveLoadEmptyArrayTransaction (array side) to decorrelate allocate_slab_index from
// atree_map_single_slab_construction.
var DictMakeTransaction = func(loopLength uint64) *SimpleTransaction {
	return simpleTransactionWithLoop(
		loopLength,
		`let _: {String: Int} = {"a": 1}`,
	)
}

var RevertibleRandomTransaction = func(loopLength uint64) *SimpleTransaction {
	return simpleTransactionWithLoop(
		loopLength,
		`revertibleRandom<UInt64>(modulo: UInt64(100))`,
	)
}

var NumberToStringConversionTransaction = func(loopLength uint64) *SimpleTransaction {
	return simpleTransactionWithLoop(
		loopLength,
		`i.toString()`,
	)
}

var ConcatenateStringTransaction = func(loopLength uint64) *SimpleTransaction {
	return simpleTransactionWithLoop(
		loopLength,
		`"x".concat(i.toString())`,
	)
}

var BorrowStringTransaction = NewSimpleTransaction(
	`
		let strings = signer.storage.borrow<&[String]>(from: /storage/ABrSt)!
		var i = 0
		var lenSum = 0
		while (i < strings.length) {
			lenSum = lenSum + strings[i].length
			i = i + 1
		}
	`,
).WithSetupTemplate(`
	signer.storage.load<[String]>(from: /storage/ABrSt)
	let strings: [String] = %s
	signer.storage.save<[String]>(strings, to: /storage/ABrSt)
`)

var CopyStringTransaction = NewSimpleTransaction(
	`
		let strings = signer.storage.copy<[String]>(from: /storage/ACpSt)!
		var i = 0
		var lenSum = 0
		while (i < strings.length) {
			lenSum = lenSum + strings[i].length
			i = i + 1
		}
	`,
).WithSetupTemplate(`
	signer.storage.load<[String]>(from: /storage/ACpSt)
	let strings: [String] = %s
	signer.storage.save<[String]>(strings, to: /storage/ACpSt)
`)

var CopyStringAndSaveADuplicateTransaction = NewSimpleTransaction(
	`
		let strings = signer.storage.copy<[String]>(from: /storage/ACpStSv)!
		var i = 0
		var lenSum = 0
		while (i < strings.length) {
			lenSum = lenSum + strings[i].length
			i = i + 1
		}
		signer.storage.save(strings, to: /storage/ACpStSv2)
	`,
).WithSetupTemplate(`
	signer.storage.load<[String]>(from: /storage/ACpStSv)
	signer.storage.load<[String]>(from: /storage/ACpStSv2)
	let strings: [String] = %s
	signer.storage.save<[String]>(strings, to: /storage/ACpStSv)
`)

var StoreAndLoadDictStringTransaction = func(dictLen uint64) *SimpleTransaction {
	return NewSimpleTransaction(
		fmt.Sprintf(
			`
				signer.storage.save<{String: String}>(%s, to: /storage/AStDSt)
				signer.storage.load<{String: String}>(from: /storage/AStDSt)
			`,
			StringDictOfLen(dictLen, 75),
		),
	)
}

var StoreLoadAndDestroyDictStringTransaction = NewSimpleTransaction(
	`
		let strings = signer.storage.load<{String: String}>(from: /storage/ALdDStD)!
		for key in strings.keys {
			strings.remove(key: key)
		}
	`,
).WithSetupTemplate(`
	signer.storage.load<{String: String}>(from: /storage/ALdDStD)
	let strings: {String: String} = %s
	signer.storage.save<{String: String}>(strings, to: /storage/ALdDStD)
`)

var BorrowDictStringTransaction = NewSimpleTransaction(
	`
		let strings = signer.storage.borrow<&{String: String}>(from: /storage/ABrDSt)!
		var lenSum = 0
		strings.forEachKey(fun (key: String): Bool {
			lenSum = lenSum + strings[key]!.length
			return true
		})
	`,
).WithSetupTemplate(`
	signer.storage.load<{String: String}>(from: /storage/ABrDSt)
	let strings: {String: String} = %s
	signer.storage.save<{String: String}>(strings, to: /storage/ABrDSt)
`)

var CopyDictStringTransaction = NewSimpleTransaction(
	`
		let strings = signer.storage.copy<{String: String}>(from: /storage/ACpDSt)!
		var lenSum = 0
		strings.forEachKey(fun (key: String): Bool {
			lenSum = lenSum + strings[key]!.length
			return true
		})
	`,
).WithSetupTemplate(`
	signer.storage.load<{String: String}>(from: /storage/ACpDSt)
	let strings: {String: String} = %s
	signer.storage.save<{String: String}>(strings, to: /storage/ACpDSt)
`)

var CopyDictStringAndSaveADuplicateTransaction = NewSimpleTransaction(
	`
		let strings = signer.storage.copy<{String: String}>(from: /storage/ACpDStSv)!
		var lenSum = 0
		strings.forEachKey(fun (key: String): Bool {
			lenSum = lenSum + strings[key]!.length
			return true
		})
		signer.storage.save(strings, to: /storage/ACpDStSv2)
	`,
).WithSetupTemplate(`
	signer.storage.load<{String: String}>(from: /storage/ACpDStSv)
	signer.storage.load<{String: String}>(from: /storage/ACpDStSv2)
	let strings: {String: String} = %s
	signer.storage.save(strings, to: /storage/ACpDStSv)
`)

var LoadDictAndDestroyItTransaction = NewSimpleTransaction(
	`
		let r <- signer.storage.load<@{String: AnyResource}>(from: /storage/DestDict)!
		destroy r
	`,
).WithSetupTemplate(`
	let r <- signer.storage.load<@{String: AnyResource}>(from: /storage/DestDict)
	destroy r
	let r2: @{String: AnyResource} <- {}
	var i = 0
	while (i < %d) {
		i = i + 1
		let d: @{String: AnyResource} <- {}
		r2[i.toString()] <-! d
	}

	signer.storage.save<@{String: AnyResource}>( <- r2, to: /storage/DestDict)
`)

var AddKeyToAccountTransaction = func(loopLength uint64) *SimpleTransaction {
	return simpleTransactionWithLoop(
		loopLength,
		`
				let key = PublicKey(
					publicKey: "f7901e9161b9b53f2e1f27b0f1e4711fcc8f234a90f55fd2068a67b152948389c0ee1e40f74a0e194ef7c2b59666270b16d52cf585fd8e65fc00958f78af77b0".decodeHex(),
					signatureAlgorithm: SignatureAlgorithm.ECDSA_secp256k1
				)
		
				signer.keys.add(
					publicKey: key,
					hashAlgorithm: HashAlgorithm.SHA3_256,
					weight: 0.0
				)
			`,
	)
}

var AddAndRevokeKeyToAccountTransaction = func(loopLength uint64) *SimpleTransaction {
	return simpleTransactionWithLoop(
		loopLength,
		`
				let key = PublicKey(
					publicKey: "f7901e9161b9b53f2e1f27b0f1e4711fcc8f234a90f55fd2068a67b152948389c0ee1e40f74a0e194ef7c2b59666270b16d52cf585fd8e65fc00958f78af77b0".decodeHex(),
					signatureAlgorithm: SignatureAlgorithm.ECDSA_secp256k1
				)
		
				let ac = signer.keys.add(
					publicKey: key,
					hashAlgorithm: HashAlgorithm.SHA3_256,
					weight: 0.0
				)
				signer.keys.revoke(keyIndex: ac.keyIndex)
			`,
	)
}

var GetAccountKeyTransaction = func(loopLength uint64) *SimpleTransaction {
	return simpleTransactionWithLoop(
		loopLength,
		`
				let key = signer.keys.get(keyIndex: 0)
			`,
	)
}

var GetContractsTransaction = func(loopLength uint64) *SimpleTransaction {
	return simpleTransactionWithLoop(
		loopLength,
		`signer.contracts.names`,
	).WithSetupTemplate(`
		var c = signer.contracts.names.length
		while c < 20 {
			// deploy contract
			let contractName = "TestContract".concat(c.toString())
			let contractCode = "access(all) contract ".concat(contractName).concat(" {}")
			signer.contracts.add(name: contractName, code: contractCode.utf8)
			c = c + 1
		}
	`)
}

var HashTransaction = func(loopLength uint64) *SimpleTransaction {
	return simpleTransactionWithLoop(
		loopLength,
		`Crypto.hash("%s".utf8, algorithm: HashAlgorithm.SHA2_256)`,
	)
}

var HashChainTransaction = func(loopLength uint64) *SimpleTransaction {
	body := fmt.Sprintf(`
				var data: [UInt8] = [1, 2, 3, 4, 5, 6, 7, 8]
				%s
			`,
		LoopTemplate(
			loopLength,
			`
					data = HashAlgorithm.SHA2_256.hash(data)
					data = HashAlgorithm.SHA2_256.hash(data)
					data = HashAlgorithm.SHA2_256.hash(data)
					data = HashAlgorithm.SHA2_256.hash(data)
					data = HashAlgorithm.SHA2_256.hash(data)
				`,
		),
	)

	return NewSimpleTransaction(body)
}

var HashSHA3Transaction = func(loopLength uint64) *SimpleTransaction {
	return simpleTransactionWithLoop(
		loopLength,
		fmt.Sprintf(`HashAlgorithm.SHA3_256.hash("%s".utf8)`, StringOfLen(32)),
	)
}

var HashKeccakTransaction = func(loopLength uint64) *SimpleTransaction {
	return simpleTransactionWithLoop(
		loopLength,
		fmt.Sprintf(`HashAlgorithm.KECCAK_256.hash("%s".utf8)`, StringOfLen(32)),
	)
}

var DirectVerifyP256Transaction = func(loopLength uint64, rawKey string, sig string, message []byte) *SimpleTransaction {
	body := fmt.Sprintf(`
				let pk = PublicKey(
					publicKey: "%s".decodeHex(),
					signatureAlgorithm: SignatureAlgorithm.ECDSA_P256
				)
				let sig = "%s".decodeHex()
				let msg = "%s".decodeHex()
				%s
			`,
		rawKey,
		sig,
		hex.EncodeToString(message),
		LoopTemplate(
			loopLength,
			`
					pk.verify(
						signature: sig,
						signedData: msg,
						domainSeparationTag: "FLOW-V0.0-user",
						hashAlgorithm: HashAlgorithm.SHA2_256
					)
				`,
		),
	)

	return NewSimpleTransaction(body)
}

var DirectVerifySecp256k1Transaction = func(loopLength uint64, rawKey string, sig string, message []byte) *SimpleTransaction {
	body := fmt.Sprintf(`
				let pk = PublicKey(
					publicKey: "%s".decodeHex(),
					signatureAlgorithm: SignatureAlgorithm.ECDSA_secp256k1
				)
				let sig = "%s".decodeHex()
				let msg = "%s".decodeHex()
				%s
			`,
		rawKey,
		sig,
		hex.EncodeToString(message),
		LoopTemplate(
			loopLength,
			`
					pk.verify(
						signature: sig,
						signedData: msg,
						domainSeparationTag: "FLOW-V0.0-user",
						hashAlgorithm: HashAlgorithm.SHA2_256
					)
				`,
		),
	)

	return NewSimpleTransaction(body)
}

var DirectVerifyBLSTransaction = func(loopLength uint64, rawKey string, sig string, message []byte) *SimpleTransaction {
	body := fmt.Sprintf(`
				let pk = PublicKey(
					publicKey: "%s".decodeHex(),
					signatureAlgorithm: SignatureAlgorithm.BLS_BLS12_381
				)
				let sig = "%s".decodeHex()
				let msg = "%s".decodeHex()
				%s
			`,
		rawKey,
		sig,
		hex.EncodeToString(message),
		LoopTemplate(
			loopLength,
			`
					pk.verify(
						signature: sig,
						signedData: msg,
						domainSeparationTag: "random_tag",
						hashAlgorithm: HashAlgorithm.KMAC128_BLS_BLS12_381
					)
				`,
		),
	)

	return NewSimpleTransaction(body)
}

var StringToLowerTransaction = func(loopLength uint64, stringLen uint64) *SimpleTransaction {
	return simpleTransactionWithLoop(
		loopLength,
		fmt.Sprintf(`
			var s = "%s"
			s = s.toLower()
		`, StringOfLen(stringLen)),
	)
}

// StringComparisonTransaction compares two short literals per iter.
// Profile: high StringComparison; zero GetValue / atree_*_construction —
// decorrelates string_comparison from get_value.
var StringComparisonTransaction = func(loopLength uint64) *SimpleTransaction {
	return simpleTransactionWithLoop(
		loopLength,
		`let _ = "the quick brown fox" == "lorem ipsum dolor sit amet"`,
	)
}

// StringComparisonLongTransaction compares two 500-char strings differing only on
// the last byte — StringComparison intensity = minLen, so each iter fires ~500 units
// (vs ~19 for the short variant). Trailing-mismatch is required; a first-byte
// mismatch lets atree short-circuit. Pushes per-tx intensity high enough for NNLS
// to recover the coefficient against storage-touching templates that absorb it
// through get_value.
var StringComparisonLongTransaction = func(loopLength uint64) *SimpleTransaction {
	s := strings.Repeat("a", 500)
	body := fmt.Sprintf(`let _ = "%s" == "%sZ"`, s, s[:499])
	return simpleTransactionWithLoop(loopLength, body)
}

// ArrayLiteralStringTransaction constructs a 26-element [String] literal per iter.
// Profile: high AtreeArrayBatchConstruction (intensity 26/iter); zero
// AtreeArrayReadIteration, transfer/copy — decorrelates batch_construction from
// read_iteration (other batch_construction templates go through the non-primitive
// transfer path, which fires both 1:1).
var ArrayLiteralStringTransaction = func(loopLength uint64) *SimpleTransaction {
	return simpleTransactionWithLoop(
		loopLength,
		`let _: [String] = [
			"a","b","c","d","e","f","g","h","i","j","k","l","m",
			"n","o","p","q","r","s","t","u","v","w","x","y","z"
		]`,
	)
}

// LoadSaveStringArrayTransaction loads a stored 50-element [String] and re-saves it.
// Profile: high AtreeArrayPopIteration without touching account.keys — decorrelates
// pop_iteration from validate_public_key / add/revoke/get_account_key, which absorb
// it in the migrationtestnet fit.
var LoadSaveStringArrayTransaction = func(loopLength uint64) *SimpleTransaction {
	return simpleTransactionWithLoop(
		loopLength,
		`let arr = signer.storage.load<[String]>(from: /storage/ArrPopSrc)
			?? panic("ArrPop: source array not set up")
		signer.storage.save(arr, to: /storage/ArrPopSrc)`,
	)
}

var GetCurrentBlockTransaction = func(loopLength uint64) *SimpleTransaction {
	return simpleTransactionWithLoop(
		loopLength,
		`getCurrentBlock()`,
	)
}

var GetBlockAtTransaction = func(loopLength uint64) *SimpleTransaction {
	return simpleTransactionWithLoop(
		loopLength,
		`let at = getCurrentBlock().height
		getBlock(at: at)`,
	)
}

// GetBlockAtCachedHeightTransaction calls getBlock(at:) N times against a
// caller-resolved height. No getCurrentBlock() in the body, isolating
// GetBlockAtHeight from GetCurrentBlockHeight.
var GetBlockAtCachedHeightTransaction = func(loopLength, height uint64) *SimpleTransaction {
	return NewSimpleTransaction(fmt.Sprintf(`
		let h: UInt64 = %d
		var i = 0
		while i < %d {
			i = i + 1
			getBlock(at: h)
		}`, height, loopLength))
}

var DestroyResourceDictionaryTransaction = func(loopLength uint64) *SimpleTransaction {
	return simpleTransactionWithLoop(
		loopLength,
		`let r: @{String: AnyResource} <- {}
		destroy r`,
	)
}

var ParseUFix64Transaction = func(loopLength uint64) *SimpleTransaction {
	return simpleTransactionWithLoop(
		loopLength,
		`let smol: UFix64? = UFix64.fromString("0.123456")`,
	)
}

var ParseFix64Transaction = func(loopLength uint64) *SimpleTransaction {
	return simpleTransactionWithLoop(
		loopLength,
		`let smol: Fix64? = Fix64.fromString("-0.123456")`,
	)
}

var ParseUInt64Transaction = func(loopLength uint64) *SimpleTransaction {
	return simpleTransactionWithLoop(
		loopLength,
		`let smol: UInt64? = UInt64.fromString("123456")`,
	)
}

var ParseInt64Transaction = func(loopLength uint64) *SimpleTransaction {
	return simpleTransactionWithLoop(
		loopLength,
		`let smol: Int64? = Int64.fromString("-123456")`,
	)
}

var ParseIntTransaction = func(loopLength uint64) *SimpleTransaction {
	return simpleTransactionWithLoop(
		loopLength,
		`let smol: Int? = Int.fromString("-12345")`,
	)
}

var IssueStorageCapabilityTransaction = func(loopLength uint64) *SimpleTransaction {
	return simpleTransactionWithLoop(
		loopLength,
		`let cap = signer.capabilities.storage.issue<&Int>(/storage/foo)`,
	)
}

var GetKeyCountTransaction = func(loopLength uint64) *SimpleTransaction {
	return simpleTransactionWithLoop(
		loopLength,
		`let count = signer.keys.count`,
	)
}

var CreateKeyECDSAP256Transaction = func(loopLength uint64, key string) *SimpleTransaction {
	body := fmt.Sprintf(`
			let publicKey = PublicKey(
			publicKey: "%s".decodeHex(),
			signatureAlgorithm: SignatureAlgorithm.ECDSA_P256
		)
	`, key)

	return simpleTransactionWithLoop(
		loopLength,
		body,
	)
}

var CreateKeyECDSAsecp256k1Transaction = func(loopLength uint64, key string) *SimpleTransaction {
	body := fmt.Sprintf(`
				let publicKey = PublicKey(
					publicKey: "%s".decodeHex(),
					signatureAlgorithm: SignatureAlgorithm.ECDSA_secp256k1
				)
			`, key)

	return simpleTransactionWithLoop(
		loopLength,
		body,
	)
}

var CreateKeyBLSBLS12381Transaction = func(loopLength uint64, key string) *SimpleTransaction {
	body := fmt.Sprintf(`
				let publicKey = PublicKey(
					publicKey: "%s".decodeHex(),
					signatureAlgorithm: SignatureAlgorithm.BLS_BLS12_381
				)
			`, key)

	return simpleTransactionWithLoop(
		loopLength,
		body,
	)
}

var ArrayInsertTransaction = func(loopLength uint64) *SimpleTransaction {
	body := fmt.Sprintf(`
				let x = [0]
				%s
			`,
		LoopTemplate(
			loopLength,
			`
					x.insert(at: i, 1)
				`,
		),
	)

	return NewSimpleTransaction(
		body,
	)
}

var ArrayInsertRemoveTransaction = func(loopLength uint64) *SimpleTransaction {
	body := fmt.Sprintf(`
				let x = [0]
				%s
			`,
		LoopTemplate(
			loopLength,
			`
					x.insert(at: 0, 1)
					x.remove(at: 1)
				`,
		),
	)

	return NewSimpleTransaction(
		body,
	)
}

var ArrayInsertSetRemoveTransaction = func(loopLength uint64) *SimpleTransaction {
	body := fmt.Sprintf(`
				let x = [0]
				%s
			`,
		LoopTemplate(
			loopLength,
			`
					x.insert(at: 0, 1)
					x[0] = i
					x.remove(at: 1)
				`,
		),
	)

	return NewSimpleTransaction(
		body,
	)
}

var ArrayInsertMapTransaction = func(loopLength uint64) *SimpleTransaction {
	body := fmt.Sprintf(`
			let x = [0]
			%s
			let addOne =
				fun (_ v: Int): Int {
					return v+1
				}
			let y = x.map(addOne)
		`,
		LoopTemplate(
			loopLength,
			`
				x.insert(at: 0, i)
			`,
		),
	)

	return NewSimpleTransaction(
		body,
	)
}

var ArrayInsertFilterTransaction = func(loopLength uint64) *SimpleTransaction {
	body := fmt.Sprintf(`
			let x = [0]
			%s
			let isEven =
				view fun (element: Int): Bool {
					return element %% 2 == 0
				}
			let y = x.filter(isEven)
		`,
		LoopTemplate(
			loopLength,
			`
				x.insert(at: 0, i)
			`,
		),
	)
	return NewSimpleTransaction(
		body,
	)
}

var ArrayAppendTransaction = func(loopLength uint64) *SimpleTransaction {
	body := fmt.Sprintf(`
			let x = [0]
			%s
		`,
		LoopTemplate(
			loopLength,
			`
				x.append(i)
			`,
		),
	)

	return NewSimpleTransaction(
		body,
	)
}

var DictInsertTransaction = func(loopLength uint64) *SimpleTransaction {
	body := fmt.Sprintf(`
			let x = {"0": 0}
			%s
		`,
		LoopTemplate(
			loopLength,
			`
				x.insert(key: i.toString(), i)
			`,
		),
	)

	return NewSimpleTransaction(
		body,
	)
}

var DictInsertRemoveTransaction = func(loopLength uint64) *SimpleTransaction {
	body := fmt.Sprintf(`
					let x = {"0": 0}
					%s
				`,
		LoopTemplate(
			loopLength,
			`
						x.insert(key: i.toString(), i)
						x.remove(key: (i-1).toString())
					`,
		),
	)

	return NewSimpleTransaction(
		body,
	)
}

var DictInsertSetRemoveTransaction = func(loopLength uint64) *SimpleTransaction {
	body := fmt.Sprintf(`
			let x = {"0": 0}
			%s
		`,
		LoopTemplate(
			loopLength,
			`
				x.insert(key: i.toString(), i)
				x[(i-1).toString()] = i
				x.remove(key: (i-1).toString())
			`,
		),
	)

	return NewSimpleTransaction(
		body,
	)
}

var DictIterCopyTransaction = func(loopLength uint64) *SimpleTransaction {
	body := fmt.Sprintf(`
			let x = {"0": 0}
			let y = {"0": 0}
			%s
			x.forEachKey(fun (key: String): Bool {
				y[key] = x[key]
				return true
			})
		`,
		LoopTemplate(
			loopLength,
			`
				x.insert(key: i.toString(), i)
			`,
		),
	)

	return NewSimpleTransaction(
		body,
	)
}

var ArrayCreateBatchTransaction = func(loopLength uint64) *SimpleTransaction {
	sumStr := "0"
	for i := 0; i < int(loopLength); i++ {
		sumStr += fmt.Sprintf(",%d", i)
	}

	body := fmt.Sprintf(`
				var i = 0
				while i < 200 {
					i = i + 1
					let a = [%s]
				}
			`, sumStr)

	return NewSimpleTransaction(
		body,
	)
}

var VerifySignatureTransaction = func(numKeys uint64, message []byte, rawKeys []string, signatures []string) *SimpleTransaction {
	keyListAdd := ""
	for i := 0; i < int(numKeys); i++ {
		keyListAdd += fmt.Sprintf(`
					keyList.add(
						PublicKey(
							publicKey: "%s".decodeHex(),
							signatureAlgorithm: SignatureAlgorithm.ECDSA_P256
						),
						hashAlgorithm: HashAlgorithm.SHA3_256,
						weight: 1.0/%d.0+0.000001 ,
					)
				`, rawKeys[i], int(numKeys),
		)
	}

	signaturesAdd := ""
	for i := 0; i < int(numKeys); i++ {
		signaturesAdd += fmt.Sprintf(`
					signatureSet.append(
						Crypto.KeyListSignature(
							keyIndex: %d,
							signature: "%s".decodeHex()
						)
					)
				`, i, signatures[i],
		)
	}

	body := fmt.Sprintf(`
				let keyList = Crypto.KeyList()

				%s

				let signatureSet: [Crypto.KeyListSignature] = []

				%s

				let domainSeparationTag = "FLOW-V0.0-user"
				let message = "%s".decodeHex()
				
				
				let valid = keyList.verify(
					signatureSet: signatureSet,
					signedData: message,
					domainSeparationTag: domainSeparationTag
				)
				if !valid {
					panic("invalid signature")
				}
				
			`, keyListAdd, signaturesAdd, hex.EncodeToString(message))

	return NewSimpleTransaction(
		body,
	)
}

var AggregateBLSAggregateSignatureTransaction = func(numSigs int, sigs []crypto2.Signature) *SimpleTransaction {
	signatures := ""
	for i := 0; i < numSigs; i++ {
		signatures += fmt.Sprintf(`
				signatures.append("%s".decodeHex())
			`, hex.EncodeToString(sigs[i].Bytes()))
	}

	body := fmt.Sprintf(`
		var signatures: [[UInt8]] = []
		%s
		BLS.aggregateSignatures(signatures)!
	`, signatures)

	return NewSimpleTransaction(
		body,
	)
}

var AggregateBLSAggregateKeysTransaction = func(numSigs int, publicKeys []string) *SimpleTransaction {
	pkString := ""
	for i := 0; i < numSigs; i++ {
		pkString += fmt.Sprintf(`
						pks.append(PublicKey(
							publicKey: "%s".decodeHex(), 
							signatureAlgorithm: SignatureAlgorithm.BLS_BLS12_381
						))
					`, publicKeys[i])
	}

	body := fmt.Sprintf(`
		let pks: [PublicKey] = []
		%s
		BLS.aggregatePublicKeys(pks)!.publicKey
	`, pkString)

	return NewSimpleTransaction(
		body,
	)
}

var BLSVerifySignatureTransaction = func(numSigs int, pks []crypto2.PublicKey, signatures []crypto2.Signature, message []byte) *SimpleTransaction {
	signaturesString := ""
	for i := 0; i < numSigs; i++ {
		signaturesString += fmt.Sprintf(`
								signatures.append("%s".decodeHex())
							`, hex.EncodeToString(signatures[i].Bytes()))
	}

	pkString := ""
	for i := 0; i < numSigs; i++ {
		pkString += fmt.Sprintf(`
						pks.append(PublicKey(
							publicKey: "%s".decodeHex(), 
							signatureAlgorithm: SignatureAlgorithm.BLS_BLS12_381
						))
					`, hex.EncodeToString(pks[i].Encode()))
	}

	body := fmt.Sprintf(`
				var pks: [PublicKey] = []
				var signatures: [[UInt8]] = []
				%s
				%s
				let aggPk = BLS.aggregatePublicKeys(pks)!
				let aggSignature = BLS.aggregateSignatures(signatures)!
				let boo = aggPk.verify(
							signature: aggSignature, 
							signedData: "%s".decodeHex(),
							domainSeparationTag: "random_tag", 
							hashAlgorithm: HashAlgorithm.KMAC128_BLS_BLS12_381)
				if !boo {
					panic("invalid signature")
				}
			`, pkString, signaturesString, hex.EncodeToString(message))

	return NewSimpleTransaction(
		body,
	)
}

var BLSVerifyProofOfPossessionTransaction = func(loopLength uint64, publicKeyString string, proofString string) *SimpleTransaction {

	body := fmt.Sprintf(`
			let p = PublicKey(
				publicKey: "%s".decodeHex(), 
				signatureAlgorithm: SignatureAlgorithm.BLS_BLS12_381
			)
			var proof = "%s".decodeHex()

			%s
		`,
		publicKeyString,
		proofString,
		LoopTemplate(
			loopLength,
			`
				var valid = p.verifyPoP(proof)
				if !valid {
					panic("invalid proof of possession")
				}
			`,
		),
	)

	return NewSimpleTransaction(
		body,
	)
}
