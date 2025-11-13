import "FlowTransactionScheduler"

access(all) contract TestContract {
    access(all) var totalSupply: UInt64
    access(all) var nfts: @[NFT]

    access(all) event SomeEvent()
    access(all) event SomeEvent2(d: {String:String})

    // scheduled transaction related code
    access(all) let HandlerStoragePath: StoragePath
    access(all) let HandlerPublicPath: PublicPath

    access(all) resource Handler: FlowTransactionScheduler.TransactionHandler {
        access(FlowTransactionScheduler.Execute)
        fun executeTransaction(id: UInt64, data: AnyStruct?) { } // noop handler
    }

    access(all) fun createHandler(): @Handler {
        return <- create Handler()
    }

    access(all) fun empty() {
    }
    access(all) fun emitEvent() {
        emit SomeEvent()
    }
    access(all) fun emitDictEvent(_ d: {String:String}) {
        emit SomeEvent2(d:d)
    }

    access(all) fun mintNFT() {
        var newNFT <- create NFT(
            id: TestContract.totalSupply,
            data: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        )
        self.nfts.append( <- newNFT)

        TestContract.totalSupply = TestContract.totalSupply + UInt64(1)
    }

    access(all) resource NFT {
        access(all) let id: UInt64
        access(all) let data: String

        init(
            id: UInt64,
            data: String,
        ) {
            self.id = id
            self.data = data
        }
    }

    init() {
        self.HandlerStoragePath = /storage/testCallbackHandler
        self.HandlerPublicPath = /public/testCallbackHandler

        self.totalSupply = 0
        self.nfts <- []
    }
}
