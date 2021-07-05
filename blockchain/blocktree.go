package blockchain

import (
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/massnetorg/mass-core/blockchain/state"
	"github.com/massnetorg/mass-core/consensus/forks"
	"github.com/massnetorg/mass-core/interfaces"
	"github.com/massnetorg/mass-core/trie/common"
	"github.com/massnetorg/mass-core/wire"
)

const (
	// minMemoryNodes is the minimum number of consecutive nodes needed
	// in memory in order to perform all necessary validation.  It is used
	// to determine when it's safe to prune nodes from memory without
	// causing constant dynamic reloading.
	minMemoryNodes = 8000
)

type BlockNode struct {
	InMainChain     bool
	Parent          *BlockNode
	Hash            *wire.Hash
	CapSum          *big.Int
	ChainID         wire.Hash
	Version         uint64
	Height          uint64
	Timestamp       time.Time
	Previous        wire.Hash
	TransactionRoot wire.Hash
	WitnessRoot     wire.Hash
	ProposalRoot    wire.Hash
	Target          *big.Int
	Challenge       wire.Hash
	Quality         *big.Int
	blockHeader     *wire.BlockHeader

	bindingState state.Trie
}

func NewBlockNode(header *wire.BlockHeader, blockHash *wire.Hash, flags BehaviorFlags) *BlockNode {
	if flags.isFlagSet(BFNoPoCCheck) {
		return &BlockNode{
			ChainID:         header.ChainID,
			Version:         header.Version,
			Height:          header.Height,
			Timestamp:       header.Timestamp,
			Previous:        header.Previous,
			TransactionRoot: header.TransactionRoot,
			WitnessRoot:     header.WitnessRoot,
			ProposalRoot:    header.ProposalRoot,
			blockHeader:     header,
		}
	}
	return &BlockNode{
		Hash:            blockHash,
		CapSum:          new(big.Int).Set(header.Target),
		ChainID:         header.ChainID,
		Version:         header.Version,
		Height:          header.Height,
		Timestamp:       header.Timestamp,
		Previous:        header.Previous,
		TransactionRoot: header.TransactionRoot,
		WitnessRoot:     header.WitnessRoot,
		ProposalRoot:    header.ProposalRoot,
		Target:          header.Target,
		Challenge:       header.Challenge,
		Quality:         header.Quality(),
		blockHeader:     header,
	}
}

// Ancestor returns the ancestor block node at the provided height by following
// the chain backwards from this node.  The returned block will be nil when a
// height is requested that is after the height of the passed node or is less
// than zero.
func (node *BlockNode) Ancestor(height uint64) *BlockNode {
	if height < 0 || height > node.Height {
		return nil
	}

	n := node
	for ; n != nil && n.Height != height; n = n.Parent {
		// Intentionally left blank
	}

	return n
}

func (node *BlockNode) BlockHeader() *wire.BlockHeader {
	return &wire.BlockHeader{
		ChainID:         node.ChainID,
		Version:         node.Version,
		Height:          node.Height,
		Timestamp:       node.Timestamp,
		Previous:        node.Previous,
		TransactionRoot: node.TransactionRoot,
		WitnessRoot:     node.WitnessRoot,
		ProposalRoot:    node.ProposalRoot,
		Target:          node.Target,
		Challenge:       node.Challenge,
		PubKey:          node.blockHeader.PubKey,
		Proof:           node.blockHeader.Proof,
		Signature:       node.blockHeader.Signature,
		BanList:         node.blockHeader.BanList,
		BindingRoot:     node.blockHeader.BindingRoot,
	}
}

func (node *BlockNode) PublicKey() interfaces.PublicKey {
	return node.blockHeader.PublicKey()
}

func (node *BlockNode) BannedPublicKeys() []interfaces.PublicKey {
	return node.blockHeader.BannedPublicKeys()
}

func (node *BlockNode) BitLength() int {
	return node.blockHeader.Proof.BitLength()
}

// Set nil to clear state
func (node *BlockNode) SetBindingState(state state.Trie) error {
	if !forks.EnforceMASSIP0002WarmUp(node.Height) {
		return nil
	}
	if state != nil && state.Hash() != node.blockHeader.BindingRoot {
		return ErrMismatchedBindingRoot
	}
	node.bindingState = state
	return nil
}

func (node *BlockNode) BindingState(stateDb state.Database) (state.Trie, error) {
	var err error
	if node.bindingState == nil {
		if !forks.EnforceMASSIP0002WarmUp(node.Height) {
			node.bindingState, err = stateDb.OpenBindingTrie(common.Hash{})
		} else {
			if (node.blockHeader.BindingRoot == common.Hash{}) {
				return nil, fmt.Errorf("unexpect empty BindingRoot at %d, %s", node.blockHeader.Height, node.Hash)
			}
			node.bindingState, err = stateDb.OpenBindingTrie(node.blockHeader.BindingRoot)
		}
		if err != nil {
			return nil, err
		}
	}
	return stateDb.CopyTrie(node.bindingState), err
}

// Returns a copy of parent state.
func (node *BlockNode) ParentBindingState(stateDb state.Database) (state.Trie, error) {
	if node.Parent == nil {
		return nil, fmt.Errorf("no parent node")
	}
	var err error
	if node.Parent.bindingState == nil {
		if !forks.EnforceMASSIP0002WarmUp(node.Parent.Height) {
			node.Parent.bindingState, err = stateDb.OpenBindingTrie(common.Hash{})
		} else {
			if (node.Parent.blockHeader.BindingRoot == common.Hash{}) {
				return nil, fmt.Errorf("unexpect empty parent BindingRoot at %d, %s", node.blockHeader.Height, node.Hash)
			}
			node.Parent.bindingState, err = stateDb.OpenBindingTrie(node.Parent.blockHeader.BindingRoot)
		}
	}
	return stateDb.CopyTrie(node.Parent.bindingState), err
}

type BlockTree struct {
	sync.RWMutex
	rootNode        *BlockNode                 // root node of blockTree
	bestNode        *BlockNode                 // newest block node in main chain
	index           map[wire.Hash]*BlockNode   // hash to BlockNode
	children        map[wire.Hash][]*BlockNode // parent to children
	orphanBlockPool *OrphanBlockPool           // orphan blocks pool
}

func NewBlockTree() *BlockTree {
	return &BlockTree{
		index:           make(map[wire.Hash]*BlockNode),
		children:        make(map[wire.Hash][]*BlockNode),
		orphanBlockPool: newOrphanBlockPool(),
	}
}

func (tree *BlockTree) bestBlockNode() *BlockNode {
	return tree.bestNode
}

func (tree *BlockTree) setBestBlockNode(node *BlockNode) {
	tree.bestNode = node
}

func (tree *BlockTree) rootBlockNode() *BlockNode {
	return tree.rootNode
}

func (tree *BlockTree) setRootBlockNode(node *BlockNode) error {
	tree.Lock()
	defer tree.Unlock()

	if tree.rootNode != nil {
		return errRootNodeAlreadyExists
	}
	tree.rootNode = node
	tree.children[node.Previous] = append(tree.children[node.Previous], node)
	tree.index[*node.Hash] = node

	return nil
}

func (tree *BlockTree) getBlockNode(hash *wire.Hash) (*BlockNode, bool) {
	tree.RLock()
	defer tree.RUnlock()
	node, exists := tree.index[*hash]
	return node, exists
}

func (tree *BlockTree) blockNode(hash *wire.Hash) *BlockNode {
	tree.RLock()
	defer tree.RUnlock()
	return tree.index[*hash]
}

func (tree *BlockTree) nodeExists(hash *wire.Hash) bool {
	tree.RLock()
	defer tree.RUnlock()
	_, exists := tree.index[*hash]
	return exists
}

func (tree *BlockTree) orphanExists(hash *wire.Hash) bool {
	return tree.orphanBlockPool.isOrphanInPool(hash)
}

// attachBlockNode attaches a leaf node
func (tree *BlockTree) attachBlockNode(node *BlockNode) error {
	tree.Lock()
	defer tree.Unlock()

	parentNode, exists := tree.index[node.Previous]
	if !exists {
		return errAttachNonLeafBlockNode
	}

	node.CapSum = node.CapSum.Add(parentNode.CapSum, node.CapSum)
	node.Parent = parentNode
	tree.index[*node.Hash] = node
	tree.children[node.Previous] = append(tree.children[node.Previous], node)
	return nil
}

// removeBlockNodeFromSlice assumes that both args are valid, and removes node from nodes
func removeBlockNodeFromSlice(nodes []*BlockNode, node *BlockNode) []*BlockNode {
	for i := range nodes {
		if nodes[i].Hash.IsEqual(node.Hash) {
			copy(nodes[i:], nodes[i+1:])
			nodes[len(nodes)-1] = nil
			return nodes[:len(nodes)-1]
		}
	}
	return nodes
}

// detachBlockNode detaches a leaf node in block tree
func (tree *BlockTree) detachBlockNode(node *BlockNode) error {
	tree.RLock()
	defer tree.RUnlock()

	if _, exists := tree.children[*node.Hash]; exists {
		return errDetachParentBlockNode
	}

	tree.children[node.Previous] = removeBlockNodeFromSlice(tree.children[node.Previous], node)
	if len(tree.children[node.Previous]) == 0 {
		delete(tree.children, node.Previous)
	}

	return nil
}

// recursiveAddChildrenCapSum recursively add certain cap number to children
func recursiveAddChildrenCapSum(tree *BlockTree, hash *wire.Hash, cap *big.Int) {
	for _, childNode := range tree.children[*hash] {
		childNode.CapSum.Add(childNode.CapSum, cap)
		recursiveAddChildrenCapSum(tree, childNode.Hash, cap)
	}
}

// expandRootBlockNode expands a new node before current root
func (tree *BlockTree) expandRootBlockNode(node *BlockNode) error {
	tree.Lock()
	defer tree.Unlock()

	if _, exists := tree.index[node.Previous]; exists {
		return errExpandChildRootBlockNode
	}

	childNodes, exists := tree.children[*node.Hash]
	if !exists {
		return errExpandOrphanRootBlockNode
	}

	for _, childNode := range childNodes {
		childNode.Parent = node
		tree.children[*node.Hash] = append(tree.children[*node.Hash], childNode)
		recursiveAddChildrenCapSum(tree, node.Hash, node.CapSum)
		tree.rootNode = node
	}
	tree.index[*node.Hash] = node
	tree.children[node.Previous] = append(tree.children[node.Previous], node)

	return nil
}

// TODO: discuss if it's ok not to prune memory blockNode index
//// cutAfterBlockNode cuts all branches depending on current node,
//// including current node itself
//func cutAfterBlockNode(tree *BlockTree, node *BlockNode) {
//
//}
//
//// removeRootBlockNode removes current root node
//func (tree *BlockTree) removeRootBlockNode() error {
//	tree.Lock()
//	defer tree.Unlock()
//
//	if tree.rootNode == tree.bestNode {
//		return errRemoveAllRootBlockNode
//	}
//	oldRoot := tree.rootNode
//
//	for _, child := range tree.children[*oldRoot.Hash] {
//		child.Parent = nil
//	}
//
//	delete(tree.index, *oldRoot.Hash)
//
//	// Remove the reference from the dependency index.
//	prevHash := node.Previous
//	if children, ok := b.depNodes[*prevHash]; ok {
//		// Find the node amongst the children of the
//		// dependencies for the Parent hash and remove it.
//		b.depNodes[*prevHash] = removeChildNode(children, node)
//
//		// Remove the map entry altogether if there are no
//		// longer any nodes which depend on the Parent hash.
//		if len(b.depNodes[*prevHash]) == 0 {
//			delete(b.depNodes, *prevHash)
//		}
//	}
//
//	return nil
//}
