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
		"empty loop",
		"EL",
		loopLength,
		"",
	)
}

var AssertTrueTransaction = func(loopLength uint64) *SimpleTransaction {
	return simpleTransactionWithLoop(
		"assert true",
		"Assert",
		loopLength,
		"assert(true)",
	)
}

var GetSignerAddressTransaction = func(loopLength uint64) *SimpleTransaction {
	return simpleTransactionWithLoop(
		"get signer address",
		"GSA",
		loopLength,
		"signer.address",
	)
}

var GetSignerPublicAccountTransaction = func(loopLength uint64) *SimpleTransaction {
	return simpleTransactionWithLoop(
		"get signer public account",
		"GSAcc",
		loopLength,
		"getAccount(signer.address)",
	)
}

var GetSignerAccountBalanceTransaction = func(loopLength uint64) *SimpleTransaction {
	return simpleTransactionWithLoop(
		"get signer account balance",
		"GSAccBal",
		loopLength,
		"signer.balance",
	)
}

var GetSignerAccountAvailableBalanceTransaction = func(loopLength uint64) *SimpleTransaction {
	return simpleTransactionWithLoop(
		"get signer account available balance",
		"GSAccAwBal",
		loopLength,
		"signer.availableBalance",
	)
}

var GetSignerAccountStorageUsedTransaction = func(loopLength uint64) *SimpleTransaction {
	return simpleTransactionWithLoop(
		"get signer account storage used",
		"GSAccSU",
		loopLength,
		"signer.storage.used",
	)
}

var GetSignerAccountStorageCapacityTransaction = func(loopLength uint64) *SimpleTransaction {
	return simpleTransactionWithLoop(
		"get signer account storage capacity",
		"GSAccSC",
		loopLength,
		"signer.storage.capacity",
	)
}

var BorrowSignerAccountFlowTokenVaultTransaction = func(loopLength uint64) *SimpleTransaction {
	return simpleTransactionWithLoop(
		"borrow signer account FlowToken.Vault",
		"BFTV",
		loopLength,
		"let vaultRef = signer.storage.borrow<auth(FungibleToken.Withdraw) &FlowToken.Vault>(from: /storage/flowTokenVault)!",
	)
}

var BorrowSignerAccountFungibleTokenReceiverTransaction = func(loopLength uint64) *SimpleTransaction {
	return simpleTransactionWithLoop(
		"borrow signer account FungibleToken.Receiver",
		"BFR",
		loopLength,
		`
			let receiverRef = getAccount(signer.address)
				.capabilities.borrow<&{FungibleToken.Receiver}>(/public/flowTokenReceiver)!
			`,
	)
}

var TransferTokensToSelfTransaction = func(loopLength uint64) *SimpleTransaction {
	return simpleTransactionWithLoop(
		"transfer tokens to self",
		"TTS",
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
		"create new account",
		"CA",
		loopLength,
		"let acct = Account(payer: signer)",
	)
}

var CreateNewAccountWithContractTransaction = func(loopLength uint64) *SimpleTransaction {
	return simpleTransactionWithLoop(
		"create new account with contract",
		"CAWC",
		loopLength,
		`
			let acct = Account(payer: signer)
			acct.contracts.add(name: "EmptyContract", code: "61636365737328616c6c2920636f6e747261637420456d707479436f6e7472616374207b7d".decodeHex())
			`,
	)
}

var DecodeHexTransaction = func(loopLength uint64) *SimpleTransaction {
	return simpleTransactionWithLoop(
		"decode hex",
		"HEX",
		loopLength,
		`"f847b84000fb479cb398ab7e31d6f048c12ec5b5b679052589280cacde421af823f93fe927dfc3d1e371b172f97ceeac1bc235f60654184c83f4ea70dd3b7785ffb3c73802038203e8".decodeHex()`,
	)
}

var RevertibleRandomTransaction = func(loopLength uint64) *SimpleTransaction {
	return simpleTransactionWithLoop(
		"revertible random",
		"RR",
		loopLength,
		`revertibleRandom<UInt64>(modulo: UInt64(100))`,
	)
}

var NumberToStringConversionTransaction = func(loopLength uint64) *SimpleTransaction {
	return simpleTransactionWithLoop(
		"number to string conversion",
		"TS",
		loopLength,
		`i.toString()`,
	)
}

var ConcatenateStringTransaction = func(loopLength uint64) *SimpleTransaction {
	return simpleTransactionWithLoop(
		"concatenate string",
		"CS",
		loopLength,
		`"x".concat(i.toString())`,
	)
}

// needs a string in storage
var BorrowStringTransaction = NewSimpleTransaction(
	"borrow string",
	"ABrSt",
).
	SetPrepareBlock(`
		let strings = signer.storage.borrow<&[String]>(from: /storage/ABrSt)!
		var i = 0
		var lenSum = 0
		while (i < strings.length) {
			lenSum = lenSum + strings[i].length
			i = i + 1
		}
	`)

var CopyStringTransaction = NewSimpleTransaction(
	"copy string",
	"ACpSt",
).
	SetPrepareBlock(`
		let strings = signer.storage.copy<[String]>(from: /storage/ACpSt)!
		var i = 0
		var lenSum = 0
		while (i < strings.length) {
			lenSum = lenSum + strings[i].length
			i = i + 1
		}
	`)

var CopyStringAndSaveADuplicateTransaction = NewSimpleTransaction(
	"copy string and save a duplicate",
	"ACpStSv",
).
	SetPrepareBlock(`
		let strings = signer.storage.copy<[String]>(from: /storage/ACpStSv)!
		var i = 0
		var lenSum = 0
		while (i < strings.length) {
			lenSum = lenSum + strings[i].length
			i = i + 1
		}
		signer.storage.save(strings, to: /storage/ACpStSv2)
	`)

var StoreAndLoadDictStringTransaction = func(dictLen uint64) *SimpleTransaction {
	return NewSimpleTransaction(
		"store and load dict string",
		"AStDSt",
	).
		SetPrepareBlock(fmt.Sprintf(`
		signer.storage.save<{String: String}>(%s, to: /storage/AStDSt)
		signer.storage.load<{String: String}>(from: /storage/AStDSt)
	`, stringDictOfLen(dictLen, 75)))
}

var StoreLoadAndDestroyDictStringTransaction = NewSimpleTransaction(
	"store load and destroy dict string",
	"ALdDStD",
).
	SetPrepareBlock(`
		let strings = signer.storage.load<{String: String}>(from: /storage/ALdDStD)!
		for key in strings.keys {
			strings.remove(key: key)
		}
	`)

var BorrowDictStringTransaction = NewSimpleTransaction(
	"borrow dict string",
	"ABrDSt",
).
	SetPrepareBlock(`
		let strings = signer.storage.borrow<&{String: String}>(from: /storage/ABrDSt)!
		var lenSum = 0
		strings.forEachKey(fun (key: String): Bool {
			lenSum = lenSum + strings[key]!.length
			return true
		})
	`)

var CopyDictStringTransaction = NewSimpleTransaction(
	"copy dict string",
	"ACpDSt",
).
	SetPrepareBlock(`
		let strings = signer.storage.copy<{String: String}>(from: /storage/ACpDSt)!
		var lenSum = 0
		strings.forEachKey(fun (key: String): Bool {
			lenSum = lenSum + strings[key]!.length
			return true
		})
	`)

var CopyDictStringAndSaveADuplicateTransaction = NewSimpleTransaction(
	"copy dict string and save a duplicate",
	"ACpDStSv",
).
	SetPrepareBlock(`
		let strings = signer.storage.copy<{String: String}>(from: /storage/ACpDStSv)!
		var lenSum = 0
		strings.forEachKey(fun (key: String): Bool {
			lenSum = lenSum + strings[key]!.length
			return true
		})
		signer.storage.save(strings, to: /storage/ACpDStSv2)
	`)

var LoadDictAndDestroyItTransaction = NewSimpleTransaction(
	"load dict and destroy it",
	"DestDict",
).
	SetPrepareBlock(`
		let r <- signer.storage.load<@{String: AnyResource}>(from: /storage/DestDict)!
		destroy r
	`)

var AddKeyToAccountTransaction = func(loopLength uint64) *SimpleTransaction {
	return simpleTransactionWithLoop(
		"add key to account",
		"KA",
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
		"add and revoke key to account",
		"KAR",
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
		"get account key",
		"KGet",
		loopLength,
		`
				let key = signer.keys.get(keyIndex: 0)
			`,
	)
}

var GetContractsTransaction = func(loopLength uint64) *SimpleTransaction {
	return simpleTransactionWithLoop(
		"get contracts",
		"GetCon",
		loopLength,
		`signer.contracts.names`,
	)
}

var HashTransaction = func(loopLength uint64) *SimpleTransaction {
	return simpleTransactionWithLoop(
		"hash",
		"H",
		loopLength,
		`Crypto.hash("%s".utf8, algorithm: HashAlgorithm.SHA2_256)`,
	)
}

var StringToLowerTransaction = func(loopLength uint64, stringLen uint64) *SimpleTransaction {
	return simpleTransactionWithLoop(
		"string to lower",
		"STL",
		loopLength,
		fmt.Sprintf(`
			var s = "%s"
			s = s.toLower()
		`, stringOfLen(stringLen)),
	)
}

var GetCurrentBlockTransaction = func(loopLength uint64) *SimpleTransaction {
	return simpleTransactionWithLoop(
		"get current block",
		"GCB",
		loopLength,
		`getCurrentBlock()`,
	)
}

var GetBlockAtTransaction = func(loopLength uint64) *SimpleTransaction {
	return simpleTransactionWithLoop(
		"get block at",
		"GBA",
		loopLength,
		`let at = getCurrentBlock().height
		getBlock(at: at)`,
	)
}

var DestroyResourceDictionaryTransaction = func(loopLength uint64) *SimpleTransaction {
	return simpleTransactionWithLoop(
		"destroy resource dictionary",
		"DRD",
		loopLength,
		`let r: @{String: AnyResource} <- {}
		destroy r`,
	)
}

var ParseUFix64Transaction = func(loopLength uint64) *SimpleTransaction {
	return simpleTransactionWithLoop(
		"parse UFix64",
		"PUFix",
		loopLength,
		`let smol: UFix64? = UFix64.fromString("0.123456")`,
	)
}

var ParseFix64Transaction = func(loopLength uint64) *SimpleTransaction {
	return simpleTransactionWithLoop(
		"parse Fix64",
		"PFix",
		loopLength,
		`let smol: Fix64? = Fix64.fromString("-0.123456")`,
	)
}

var ParseUInt64Transaction = func(loopLength uint64) *SimpleTransaction {
	return simpleTransactionWithLoop(
		"parse UInt64",
		"PUInt64",
		loopLength,
		`let smol: UInt64? = UInt64.fromString("123456")`,
	)
}

var ParseInt64Transaction = func(loopLength uint64) *SimpleTransaction {
	return simpleTransactionWithLoop(
		"parse Int64",
		"PInt64",
		loopLength,
		`let smol: Int64? = Int64.fromString("-123456")`,
	)
}

var ParseIntTransaction = func(loopLength uint64) *SimpleTransaction {
	return simpleTransactionWithLoop(
		"parse Int",
		"PInt",
		loopLength,
		`let smol: Int? = Int.fromString("-12345")`,
	)
}

var IssueStorageCapabilityTransaction = func(loopLength uint64) *SimpleTransaction {
	return simpleTransactionWithLoop(
		"issue storage capability",
		"ISCap",
		loopLength,
		`let cap = signer.capabilities.storage.issue<&Int>(/storage/foo)`,
	)
}

var GetKeyCountTransaction = func(loopLength uint64) *SimpleTransaction {
	return simpleTransactionWithLoop(
		"Get key count",
		"GKC",
		loopLength,
		`let count = signer.keys.count`,
	)
}

var CreateKeyECDSAP256Transaction = func(loopLength uint64) *SimpleTransaction {
	seed := make([]byte, crypto.MinSeedLength)
	for i := range seed {
		seed[i] = 0
	}

	privateKey, err := crypto.GeneratePrivateKey(crypto.ECDSA_P256, seed)
	if err != nil {
		panic(err)
	}
	key := hex.EncodeToString(privateKey.PublicKey().Encode())

	body := fmt.Sprintf(`
			let publicKey = PublicKey(
			publicKey: "%s".decodeHex(),
			signatureAlgorithm: SignatureAlgorithm.ECDSA_P256
		)
	`, key)

	return simpleTransactionWithLoop(
		"Create Key ECDSA_P256",
		"CrKeyP256",
		loopLength,
		body,
	)
}

var CreateKeyEDCSAsecp256k1Transaction = func(loopLength uint64) *SimpleTransaction {
	return simpleTransactionWithLoop(
		"Create Key ECDSA_secp256k1",
		"CrKeysecp256k1",
		loopLength,
		`
			let publicKey = PublicKey(
				publicKey: "PUBLIC_KEY_PLACEHOLDER".decodeHex(),
				signatureAlgorithm: SignatureAlgorithm.ECDSA_secp256k1
			)
		`,
	)
}

var CreateKeyBLSBLS12381Transaction = func(loopLength uint64) *SimpleTransaction {
	return simpleTransactionWithLoop(
		"Create Key BLS_BLS12_381",
		"CrKeyBLS",
		loopLength,
		`
			let publicKey = PublicKey(
				publicKey: "PUBLIC_KEY_PLACEHOLDER".decodeHex(),
				signatureAlgorithm: SignatureAlgorithm.BLS_BLS12_381
			)
		`,
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
		"Array insert",
		"ArrIns",
	).
		SetPrepareBlock(body)
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
		"Array insert remove",
		"ArrInsDel",
	).
		SetPrepareBlock(body)
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
		"Array insert set remove",
		"ArrInsSetDel",
	).
		SetPrepareBlock(body)
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
		"Array insert map",
		"ArrInsMap",
	).
		SetPrepareBlock(body)
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
		"Array insert filter",
		"ArrInsFilt",
	).
		SetPrepareBlock(body)
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
		"Dict insert",
		"DictIns",
	).
		SetPrepareBlock(body)
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
		"Dict insert remove",
		"DictInsDel",
	).
		SetPrepareBlock(body)
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
		"Dict insert set remove",
		"DictInsSetDel",
	).
		SetPrepareBlock(body)
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
		"Dict iter copy",
		"DictIterCopy",
	).
		SetPrepareBlock(body)
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
		"Array Create Batch",
		"ArrCB",
	).
		SetPrepareBlock(body)
}

var VerifySignatureTransaction = func(numKeys uint64, signatures []string) *SimpleTransaction {
	message := []byte("hello world")

	rawKeys := make([]string, numKeys)
	signers := make([]crypto.Signer, numKeys)

	for i := 0; i < int(numKeys); i++ {
		seed := make([]byte, crypto.MinSeedLength)
		_, err := rand.Read(seed)
		if err != nil {
			panic(fmt.Errorf("failed to generate seed: %w", err))
		}

		privateKey, err := crypto.GeneratePrivateKey(crypto.ECDSA_P256, seed)
		if err != nil {
			panic(fmt.Errorf("failed to generate private key: %w", err))
		}
		rawKeys[i] = hex.EncodeToString(privateKey.PublicKey().Encode())
		sig, err := crypto.NewInMemorySigner(privateKey, crypto.SHA3_256)
		if err != nil {
			panic(fmt.Errorf("failed to generate signer: %w", err))
		}
		signers[i] = sig
	}

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
		"Verify signature",
		"VerSig",
	).
		SetPrepareBlock(body)
}

var AggregateBLSAggregateSignatureTransaction = func(numSigs int, sigs []string) *SimpleTransaction {
	signatures := ""
	for i := 0; i < numSigs; i++ {
		signatures += fmt.Sprintf(`
				signatures.append("%s".decodeHex())
			`, sigs[i])
	}

	body := fmt.Sprintf(`
		var signatures: [[UInt8]] = []
		%s
		BLS.aggregateSignatures(signatures)!
	`, signatures)

	return NewSimpleTransaction(
		"Aggregate BLS aggregate signature",
		"BLSAggSig",
	).
		SetPrepareBlock(body)
}

var AggregateBLSAggregateKeysTransaction = func(numSigs int) *SimpleTransaction {
	pks := make([]crypto2.PublicKey, 0, numSigs)
	signatureAlgorithm := crypto2.BLSBLS12381
	input := make([]byte, 100)
	_, err := rand.Read(input)
	if err != nil {
		panic(fmt.Errorf("failed to generate random data to sign: %w", err))
	}

	for i := 0; i < numSigs; i++ {
		seed := make([]byte, crypto2.KeyGenSeedMinLen)
		_, err := rand.Read(seed)
		if err != nil {
			panic(fmt.Errorf("failed to generate seed: %w", err))
		}
		sk, err := crypto.GeneratePrivateKey(signatureAlgorithm, seed)
		if err != nil {
			panic(fmt.Errorf("failed to generate private key: %w", err))
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
		"Aggregate BLS aggregate keys",
		"BLSAggKey",
	).
		SetPrepareBlock(body)
}

var BLSVerifySignatureTransaction = func(numSigs int, pks []crypto2.PublicKey, signatures []string) *SimpleTransaction {
	message := []byte("random_message")

	signaturesString := ""
	for i := 0; i < numSigs; i++ {
		signaturesString += fmt.Sprintf(`
								signatures.append("%s".decodeHex())
							`, signatures[i])
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
		"BLS verify signature",
		"BLSVerSig",
	).
		SetPrepareBlock(body)
}

var BLSVerifyProofOfPossessionTransaction = func(loopLength uint64) *SimpleTransaction {
	signatureAlgorithm := crypto2.BLSBLS12381
	seed := make([]byte, crypto2.KeyGenSeedMinLen)
	_, err := rand.Read(seed)
	if err != nil {
		panic(fmt.Errorf("failed to generate seed: %w", err))
	}
	sk, err := crypto.GeneratePrivateKey(signatureAlgorithm, seed)
	if err != nil {
		panic(fmt.Errorf("failed to generate private key: %w", err))
	}
	pk := sk.PublicKey()

	proof, err := crypto2.BLSGeneratePOP(sk)
	if err != nil {
		panic(fmt.Errorf("failed to generate proof of possession: %w", err))
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
		LoopTemplate(loopLength, `
							var valid = p.verifyPoP(proof)
							if !valid {
								panic("invalid proof of possession")
							}`))

	return NewSimpleTransaction(
		"BLS verify proof of possession",
		"BLSVerPoP",
	).
		SetPrepareBlock(body)
}
