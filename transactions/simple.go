package transactions

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"

	crypto2 "github.com/onflow/crypto"
	"github.com/onflow/flow-go-sdk/crypto"
)

// for end users, there is a bunch of constructor functions which each represent a simple template

// SIMPLE TRANSACTIONS

var EmptyLoopTransaction = func(loopLength uint64) *SimpleTransaction {
	return simpleTransactionWithLoop(
		loopLength,
		"",
	)
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

var StringToLowerTransaction = func(loopLength uint64, stringLen uint64) *SimpleTransaction {
	return simpleTransactionWithLoop(
		loopLength,
		fmt.Sprintf(`
			var s = "%s"
			s = s.toLower()
		`, StringOfLen(stringLen)),
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

var CreateKeyECDSAP256Transaction = func(loopLength uint64) (*SimpleTransaction, error) {
	seed := make([]byte, crypto.MinSeedLength)
	for i := range seed {
		seed[i] = 0
	}
	privateKey, err := crypto.GeneratePrivateKey(crypto.ECDSA_P256, seed)
	if err != nil {
		return nil, err
	}
	key := hex.EncodeToString(privateKey.PublicKey().Encode())

	body := fmt.Sprintf(`
			let publicKey = PublicKey(
			publicKey: "%s".decodeHex(),
			signatureAlgorithm: SignatureAlgorithm.ECDSA_P256
		)
	`, key)

	return simpleTransactionWithLoop(
		loopLength,
		body,
	), nil
}

var CreateKeyECDSAsecp256k1Transaction = func(loopLength uint64) (*SimpleTransaction, error) {
	seed := make([]byte, crypto.MinSeedLength)
	for i := range seed {
		seed[i] = 0
	}

	privateKey, err := crypto.GeneratePrivateKey(crypto.ECDSA_secp256k1, seed)
	if err != nil {
		return nil, err
	}
	key := hex.EncodeToString(privateKey.PublicKey().Encode())

	body := fmt.Sprintf(`
				let publicKey = PublicKey(
					publicKey: "%s".decodeHex(),
					signatureAlgorithm: SignatureAlgorithm.ECDSA_secp256k1
				)
			`, key)

	return simpleTransactionWithLoop(
		loopLength,
		body,
	), nil
}

var CreateKeyBLSBLS12381Transaction = func(loopLength uint64) (*SimpleTransaction, error) {
	seed := make([]byte, crypto.MinSeedLength)
	for i := range seed {
		seed[i] = 0
	}

	privateKey, err := crypto.GeneratePrivateKey(crypto.BLS_BLS12_381, seed)
	if err != nil {
		return nil, err
	}
	key := hex.EncodeToString(privateKey.PublicKey().Encode())

	body := fmt.Sprintf(`
				let publicKey = PublicKey(
					publicKey: "%s".decodeHex(),
					signatureAlgorithm: SignatureAlgorithm.BLS_BLS12_381
				)
			`, key)

	return simpleTransactionWithLoop(
		loopLength,
		body,
	), nil
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

var AggregateBLSAggregateKeysTransaction = func(numSigs int) (*SimpleTransaction, error) {
	pks := make([]crypto2.PublicKey, 0, numSigs)
	signatureAlgorithm := crypto2.BLSBLS12381
	input := make([]byte, 100)
	_, err := rand.Read(input)
	if err != nil {
		return nil, err
	}

	for i := 0; i < numSigs; i++ {
		seed := make([]byte, crypto2.KeyGenSeedMinLen)
		_, err := rand.Read(seed)
		if err != nil {
			return nil, err
		}
		sk, err := crypto.GeneratePrivateKey(signatureAlgorithm, seed)
		if err != nil {
			return nil, err
		}

		pks = append(pks, sk.PublicKey())
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
		let pks: [PublicKey] = []
		%s
		BLS.aggregatePublicKeys(pks)!.publicKey
	`, pkString)

	return NewSimpleTransaction(
		body,
	), nil
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

var BLSVerifyProofOfPossessionTransaction = func(loopLength uint64) (*SimpleTransaction, error) {
	signatureAlgorithm := crypto2.BLSBLS12381
	seed := make([]byte, crypto2.KeyGenSeedMinLen)
	_, err := rand.Read(seed)
	if err != nil {
		return nil, err
	}
	sk, err := crypto.GeneratePrivateKey(signatureAlgorithm, seed)
	if err != nil {
		return nil, err
	}
	pk := sk.PublicKey()

	proof, err := crypto2.BLSGeneratePOP(sk)
	if err != nil {
		return nil, err
	}

	body := fmt.Sprintf(`
			let p = PublicKey(
				publicKey: "%s".decodeHex(), 
				signatureAlgorithm: SignatureAlgorithm.BLS_BLS12_381
			)
			var proof = "%s".decodeHex()

			%s
		`,
		hex.EncodeToString(pk.Encode()),
		hex.EncodeToString(proof.Bytes()),
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
	), nil
}
