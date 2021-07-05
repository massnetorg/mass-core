package blockchain

import "github.com/massnetorg/mass-core/massutil"

func (chain *Blockchain) TstgetPrevNodeFromBlock(block *massutil.Block) (*BlockNode, error) {
	return chain.getPrevNodeFromBlock(block)
}

func (chain *Blockchain) TstFetchInputTransactions(node *BlockNode, block *massutil.Block) (TxStore, error) {
	return chain.fetchInputTransactions(node, block)
}
