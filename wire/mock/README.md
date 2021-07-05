# mock 使用说明

## 简要说明

目前本包可以自动模拟构建最多 1000 个区块（高度截至 999），已有的模拟模式为 `Auto` 模式。  
构建区块使用的模板数据文件位于`template_data`目录，其中：
* `poc_keys` 记录模板区块使用的poc区块签名私钥
* `template_blks` 存放模板区块（高度0~1000）
* `wallet_keys` 存放用于交易签名的私钥，通常第一个为coinbase私钥

## Auto 模式

`Auto` 模式可以构建指定高度个区块，并指定每个区块包含多少笔非 `Coinbase` 交易，具体的使用方法如下：

```go
	opt := &Option{
		Mode:        Auto, // 指定模拟模式为 Auto
		TotalHeight: 20, // 模拟的总区块数量
		TxPerBlock:  10, // 每个区块包含（非 Coinbase） 最大交易数量
		MinNormalTxPerBlock: 0, // 最小普通交易数(除coinbase),从块challengeInterval+1开始生效
		TxScale: [4]byte, // 每个区块交易构成概率比（普通:锁定:抵押:提现，提现包括抵押提现和锁定提现)， 默认1:1:15:1
		FrozenPeriodRange: [2]byte, // 锁定高度取值范围，默认[10,50)
		BitLength       int,
	}
	chain, err := NewMockedChain(opt)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	for _, blk := range chain.Blocks() {
		fmt.Println("height", blk.Header.Height)
		for i, tx := range blk.Transactions {
			fmt.Printf("index %d, hash %s, input count %d, output count %d\n", i, tx.TxHash().String(), len(tx.TxIn), len(tx.TxOut))
		}
		fmt.Println()
	}
```

## genesis block

本模拟器使用的创世区块信息如下：

```go
var genesisCoinbaseTx = wire.MsgTx{
	Version: 1,
	TxIn: []*wire.TxIn{
		{
			PreviousOutPoint: wire.OutPoint{
				Hash:  wire.Hash{},
				Index: wire.MaxPrevOutIndex,
			},
			Sequence: wire.MaxTxInSequenceNum,
			Witness:  wire.TxWitness{},
		},
	},
	TxOut: []*wire.TxOut{
		{
			Value:    0x47868c000,
			PkScript: mustDecodeString("00200bcd3feec8beb08b3ff1983c7b11efb4b40a83181a02df5e9437c26e662a9433"),
		},
	},
	LockTime: 0,
	Payload:  mustDecodeString("000000000000000000000000"),
}

var genesisHeader = wire.BlockHeader{
	ChainID:         mustDecodeHash("7a8d8d32fdd265023a333432e4776e2cfe766488776232bd6c12d393e9d8a4b8"),
	Version:         1,
	Height:          0,
	Timestamp:       time.Unix(0x5d42d440, 0), // 2019-08-01 12:00:00 +0000 UTC, 1564660800
	Previous:        mustDecodeHash("0000000000000000000000000000000000000000000000000000000000000000"),
	TransactionRoot: mustDecodeHash("1b326cf27c011dbf90c9b72b5b5d3c5f77887cb92532f6319105bff117398e8b"),
	WitnessRoot:     mustDecodeHash("1b326cf27c011dbf90c9b72b5b5d3c5f77887cb92532f6319105bff117398e8b"),
	ProposalRoot:    mustDecodeHash("9663440551fdcd6ada50b1fa1b0003d19bc7944955820b54ab569eb9a7ab7999"),
	Target:          hexToBigInt("0f224d4a00"), // 65000000000
	Challenge:       mustDecodeHash("033e99348a6182c432ea41b5bb52ef5f8089eb7dcee93b3ef8d1ff784841e049"),
	PubKey:          mustDecodePoCPublicKey("023136096e180bb0d49493dbd2751949238a3b9f34cc7dd940397cc5542275ffa2"),
	Proof: &poc.Proof{
		X:         mustDecodeString("0e0168"),
		XPrime:    mustDecodeString("adf7f4"),
		BitLength: 24,
	},
	Signature: mustDecodePoCSignature("304402201694be1a574459fa1271d1f4afed225f0bfb2ea5896a15c59ab84f9befc0a3290220179bffe253bcc9f84664d59224fdf0b2148a74124bd1f4cfb3271bc224097b7d"),
	BanList:   make([]*pocec.PublicKey, 0),
}

var genesisBlock = wire.MsgBlock{
	Header: genesisHeader,
	Proposals: wire.ProposalArea{
		PunishmentArea: make([]*wire.FaultPubKey, 0),
		OtherArea:      make([]*wire.NormalProposal, 0),
	},
	Transactions: []*wire.MsgTx{&genesisCoinbaseTx},
}

var genesisHash = mustDecodeHash("e7168e5b1b6a57bf1d19a81369d94c6d34e54a85bddf4ed7a25e39022b4503a4")

var genesisChainID = mustDecodeHash("7a8d8d32fdd265023a333432e4776e2cfe766488776232bd6c12d393e9d8a4b8")
```