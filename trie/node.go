package trie

import (
	"errors"
	"fmt"

	"github.com/gogo/protobuf/proto"
	triepb "github.com/massnetorg/mass-core/trie/pb"
)

var indices = []string{"0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b", "c", "d", "e", "f", "[17]"}

var (
	ErrInvalidArgument = errors.New("invalid argument")
	// ErrInvalidProtoToNode = errors.New("Pb Message cannot be converted into Trie Node")
	ErrUnknownChildTypeOfFull  = errors.New("unknown child type of fullnode")
	ErrUnknownChildTypeOfShort = errors.New("unknown child type of shortnode")
	ErrUnknownChildrenType     = errors.New("unknown children type")
)

// Flag to identify the type of node
type ty int

const (
	unknown ty = iota
	full
	short
	valueType
	hashType
)

const (
	protoChildHash uint32 = iota
	protoChildValue
	protoChildEncShort
	protoChildShortKey
)

type node interface {
	fstring(string) string
	cache() (hashNode, bool)
}

type (
	fullNode struct {
		Children [17]node // Actual trie node data to encode/decode (needs custom encoder)
		flags    nodeFlag
	}
	shortNode struct {
		Key   []byte
		Val   node
		flags nodeFlag
	}
	hashNode  []byte
	valueNode []byte
)

// nilValueNode is used when collapsing internal trie nodes for hashing, since
// unset children need to serialize correctly.
var nilValueNode = valueNode(nil)

func (n *fullNode) copy() *fullNode   { copy := *n; return &copy }
func (n *shortNode) copy() *shortNode { copy := *n; return &copy }

// nodeFlag contains caching-related metadata about a node.
type nodeFlag struct {
	hash  hashNode // cached hash of the node (may be nil)
	dirty bool     // whether the node has changes that must be written to the database
}

func (n *fullNode) cache() (hashNode, bool)  { return n.flags.hash, n.flags.dirty }
func (n *shortNode) cache() (hashNode, bool) { return n.flags.hash, n.flags.dirty }
func (n hashNode) cache() (hashNode, bool)   { return nil, true }
func (n valueNode) cache() (hashNode, bool)  { return nil, true }

// Pretty printing.
func (n *fullNode) String() string  { return n.fstring("") }
func (n *shortNode) String() string { return n.fstring("") }
func (n hashNode) String() string   { return n.fstring("") }
func (n valueNode) String() string  { return n.fstring("") }

func (n *fullNode) fstring(ind string) string {
	resp := fmt.Sprintf("[\n%s  ", ind)
	for i, node := range &n.Children {
		if node == nil {
			resp += fmt.Sprintf("%s: <nil> ", indices[i])
		} else {
			resp += fmt.Sprintf("%s: %v", indices[i], node.fstring(ind+"  "))
		}
	}
	return resp + fmt.Sprintf("\n%s] ", ind)
}
func (n *shortNode) fstring(ind string) string {
	return fmt.Sprintf("{%x: %v} ", n.Key, n.Val.fstring(ind+"  "))
}
func (n hashNode) fstring(ind string) string {
	return fmt.Sprintf("<%x> ", []byte(n))
}
func (n valueNode) fstring(ind string) string {
	return fmt.Sprintf("%x ", []byte(n))
}

// func mustDecodeNode(hash, buf []byte) node {
// 	n, err := decodeNode(hash, buf)
// 	if err != nil {
// 		panic(fmt.Sprintf("node %x: %v", hash, err))
// 	}
// 	return n
// }

// // decodeNode parses the RLP encoding of a trie node.
// func decodeNode(hash, buf []byte) (node, error) {
// 	if len(buf) == 0 {
// 		return nil, io.ErrUnexpectedEOF
// 	}
// 	elems, _, err := rlp.SplitList(buf)
// 	if err != nil {
// 		return nil, fmt.Errorf("decode error: %v", err)
// 	}
// 	switch c, _ := rlp.CountValues(elems); c {
// 	case 2:
// 		n, err := decodeShort(hash, elems)
// 		return n, wrapError(err, "short")
// 	case 17:
// 		n, err := decodeFull(hash, elems)
// 		return n, wrapError(err, "full")
// 	default:
// 		return nil, fmt.Errorf("invalid number of list elements: %v", c)
// 	}
// }

func (n *shortNode) toProto() (*triepb.Node, error) {
	pb := &triepb.Node{
		Children: make([]*triepb.Child, 2),
	}
	pb.Children[0] = &triepb.Child{Type: protoChildShortKey, Val: n.Key}
	switch vn := n.Val.(type) {
	case hashNode:
		pb.Children[1] = &triepb.Child{Type: protoChildHash, Val: vn}
	case valueNode:
		pb.Children[1] = &triepb.Child{Type: protoChildValue, Val: vn}
	default:
		return nil, ErrUnknownChildTypeOfShort
	}
	return pb, nil
}

func encodeNode(n node) (enc []byte, err error) {
	var pb *triepb.Node

	switch nn := n.(type) {
	case *fullNode:
		pb = &triepb.Node{
			Children: make([]*triepb.Child, 17),
		}
		for i, child := range nn.Children[:17] {
			switch cn := child.(type) {
			case hashNode:
				pb.Children[i] = &triepb.Child{Type: protoChildHash, Val: cn}
			case valueNode:
				pb.Children[i] = &triepb.Child{Type: protoChildValue, Val: cn}
			case nil:
				pb.Children[i] = &triepb.Child{Type: protoChildValue, Val: nil}
			case *shortNode:
				nnpb, err := cn.toProto()
				if err != nil {
					return nil, err
				}
				enc, err := proto.Marshal(nnpb)
				if err != nil {
					return nil, err
				}
				pb.Children[i] = &triepb.Child{Type: protoChildEncShort, Val: enc}
			default:
				return nil, ErrUnknownChildTypeOfFull
			}
		}
	case *shortNode:
		pb, err = nn.toProto()
		if err != nil {
			return nil, err
		}
	case hashNode:
		pb = &triepb.Node{
			Children: []*triepb.Child{
				{Type: protoChildHash, Val: nn},
			},
		}
	case valueNode:
		pb = &triepb.Node{
			Children: []*triepb.Child{
				{Type: protoChildValue, Val: nn},
			},
		}
	default:
		return nil, ErrInvalidArgument
	}
	return proto.Marshal(pb)
}

func decodeNode(hash, buf []byte) (node, error) {
	pb := new(triepb.Node)
	err := proto.Unmarshal(buf, pb)
	if err != nil {
		return nil, err
	}

	switch len(pb.Children) {
	case 17:
		n := new(fullNode)
		n.flags = nodeFlag{hash: hash}
		for i := 0; i < 17; i++ {
			if pb.Children[i].Val == nil {
				n.Children[i] = nil
				continue
			}
			switch pb.Children[i].Type {
			case protoChildHash:
				n.Children[i] = hashNode(pb.Children[i].Val)
			case protoChildValue:
				n.Children[i] = valueNode(pb.Children[i].Val)
			case protoChildEncShort:
				cn, err := decodeNode(nil, pb.Children[i].Val)
				if err != nil {
					return nil, err
				}
				if _, ok := cn.(*shortNode); !ok {
					return nil, errors.New("decoded node not a shortnode")
				}
				n.Children[i] = cn
			default:
				return nil, ErrUnknownChildTypeOfFull
			}
		}
		return n, nil
	case 2:
		n := new(shortNode)
		n.flags = nodeFlag{hash: hash}
		n.Key = compactToHex(pb.Children[0].Val) // must compactToHex
		switch pb.Children[1].Type {
		case protoChildHash:
			n.Val = hashNode(pb.Children[1].Val)
		case protoChildValue:
			n.Val = valueNode(pb.Children[1].Val)
		default:
			return nil, ErrUnknownChildTypeOfShort
		}
		return n, nil
	case 1:
		switch pb.Children[0].Type {
		case protoChildHash:
			return hashNode(pb.Children[0].Val), nil
		case protoChildValue:
			return valueNode(pb.Children[0].Val), nil
		}
	}
	return nil, ErrUnknownChildrenType
}

// func ToProto(n node) (proto.Message, error) {
// 	pbNodes := new(triepb.Nodes)
// 	switch v := (n).(type) {
// 	case *fullNode:
// 		pbNodes.Val = make([]*triepb.Node, 17)
// 		for i, child := range v.Children[:17] {
// 			switch cn := (child).(type) {
// 			case hashNode:
// 				pbNodes.Val[i] = &triepb.Node{IsHash: true, Val: cn}
// 			case valueNode:
// 				pbNodes.Val[i] = &triepb.Node{IsHash: false, Val: cn}
// 			case nil:
// 				pbNodes.Val[i] = &triepb.Node{IsHash: false, Val: nil}
// 			case *shortNode:
// 				fmt.Println("short in full node: ", i, len(v.Children), cn, child)
// 				return nil, errors.New("Tring to proto full node without hash")
// 			default:
// 				fmt.Println("full node: ", i, len(v.Children), cn, child)
// 				return nil, errors.New("Tring to proto full node without hash")
// 			}
// 		}
// 	case *shortNode:
// 		fmt.Println("to short proto: ", n)
// 		pbNodes.Val = make([]*triepb.Node, 2)
// 		pbNodes.Val[0] = &triepb.Node{IsHash: false, Val: v.Key}
// 		switch n := v.Val.(type) {
// 		case hashNode:
// 			pbNodes.Val[1] = &triepb.Node{IsHash: true, Val: n}
// 		case valueNode:
// 			pbNodes.Val[1] = &triepb.Node{IsHash: false, Val: n}
// 		default:
// 			return nil, errors.New("Tring to proto short node without hash")
// 		}
// 	case hashNode:
// 		fmt.Println("to hash proto: ", n)
// 		pbNodes.Val = make([]*triepb.Node, 1)
// 		pbNodes.Val[0] = &triepb.Node{IsHash: true, Val: v}
// 	case valueNode:
// 		fmt.Println("to value proto: ", n)
// 		pbNodes.Val = make([]*triepb.Node, 1)
// 		pbNodes.Val[0] = &triepb.Node{IsHash: false, Val: v}
// 	default:
// 		return nil, ErrInvalidArgument
// 	}
// 	return pbNodes, nil
// }

// func typeOfNode(n *triepb.Nodes) (ty, error) {
// 	if n == nil {
// 		return unknown, ErrInvalidArgument
// 	}
// 	switch len(n.Val) {
// 	case 17:
// 		return full, nil
// 	case 2:
// 		return short, nil
// 	case 1:
// 		if n.Val[0].IsHash {
// 			return hashType, nil
// 		}
// 		return valueType, nil
// 	default:
// 		return unknown, errors.New("unknow type of pbNode")
// 	}
// }

// func FromProto(msg proto.Message) (node, error) {
// 	if msg, ok := msg.(*triepb.Nodes); ok {
// 		switch len(msg.Val) {
// 		case 17:
// 			n := new(fullNode)
// 			for i := range n.Children {
// 				if msg.Val[i].Val == nil {
// 					n.Children[i] = nil
// 				} else {
// 					if msg.Val[i].IsHash {
// 						n.Children[i] = hashNode(msg.Val[i].Val)
// 					} else {
// 						n.Children[i] = valueNode(msg.Val[i].Val)
// 					}
// 				}
// 			}
// 			return n, nil
// 		case 2:
// 			n := new(shortNode)
// 			n.Key = compactToHex(msg.Val[0].Val)
// 			fmt.Println("FromProto key: ", n.Key)
// 			if msg.Val[1].IsHash {
// 				n.Val = hashNode(msg.Val[1].Val)
// 			} else {
// 				n.Val = valueNode(msg.Val[1].Val)
// 			}
// 			return n, nil
// 		case 1:
// 			if msg.Val[0].IsHash {
// 				return hashNode(msg.Val[0].Val), nil
// 			}
// 			return valueNode(msg.Val[0].Val), nil
// 		default:
// 			return nil, ErrInvalidProtoToNode
// 		}
// 	}
// 	return nil, ErrInvalidProtoToNode
// }
