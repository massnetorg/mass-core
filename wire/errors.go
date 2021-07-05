package wire

import (
	"errors"
)

var (
	ErrInvalidCodecMode          = errors.New("invalid codec mode for wire")
	errTooManyTxsInBlock         = errors.New("too many transactions to fit into a block")
	errWrongProposalType         = errors.New("wrong type of proposal on otherArea")
	errInvalidFaultPubKey        = errors.New("invalid FaultPubKey, different PublicKey")
	errInvalidPlaceHolder        = errors.New("invalid placeHolder for non-Punishment ProposalArea")
	errNoTxInputs                = errors.New("transaction has no inputs")
	errNoTransactions            = errors.New("cannot validate witness commitment of block without transactions")
	errFaultPubKeyNoPubKey       = errors.New("pubKey not exists in FaultPubKey")
	errFaultPubKeyNoTestimony    = errors.New("testimony not enough in FaultPubKey")
	errFaultPubKeyWrongHeight    = errors.New("testimony height not equal in FaultPubKey")
	errFaultPubKeyWrongBigLength = errors.New("testimony bitLength not equal in FaultPubKey")
	errFaultPubKeySameBlock      = errors.New("testimony block hash is equal in FaultPubKey")
	errFaultPubKeyWrongPubKey    = errors.New("testimony pubKey not equal in FaultPubKey")
	errFaultPubKeyNoHash         = errors.New("testimony header can not get hash in FaultPubKey")
	errFaultPubKeyWrongSignature = errors.New("testimony header signature is wrong in FaultPubKey")
	errUnknownPubKeyType         = errors.New("unknown public_key type")
	errUnknownSignatureType      = errors.New("unknown signature type")
	errWrongBlockVersion         = errors.New("wrong block version")
	errMisusePubKeyType          = errors.New("misuse of public_key type")
	errMisuseSignatureType       = errors.New("misuse of signature type")
	errMisuseProofType           = errors.New("misuse of proof type")
	errMisuseBindingRoot         = errors.New("misuse of binding root")
)
