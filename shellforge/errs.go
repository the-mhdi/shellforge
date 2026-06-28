package shellforge

import (
	"errors"
)

var ErrClientPublicInvalidLen = errors.New("client public key len is invalid")
var ErrClientPubKeyInvalid = errors.New(" client provided invalid public key for encryption")
var ErrServerKeyGenProblem = errors.New("Daemon couldnt generate ephimeral key pair for session encryption")
var ErrServerSharedSecertGen = errors.New("Daemon couldnt compute Classical Shared Secret (Diffie-Hellman) ")
var ErrClientWriteKeyGen = errors.New("Daemon couldnt compute client write key ")
var ErrServertWriteKeyGen = errors.New("Daemon couldnt compute Server write key ")
var ErrTooManyAuthRetry = errors.New("too many auth retry by the client")
var ErrUserDoesNotExist = errors.New("ErrUserDoesNotExist")
var ErrRootLoginNotAllowed = errors.New("ErrRootLoginNotAllowed")
var ErrLoginNotAllowed = errors.New("ErrLoginNotAllowed")
var ErrUnsupportedKEX = errors.New("server doesnt suppport kex algo")
var ErrUnsupportedCipher = errors.New("server doesnt suppport provided cipher")
var ErrNonEligibleKey = errors.New("Non-eligible key asked for a temporary shell")
var ErrInvalidSignature = errors.New("ErrInvalidSignature")
var ErrDBKeyRetrival = errors.New("ErrDBKeyRetrival")
var ErrMaxActiveSessions = errors.New("maximum active sessions")

var ErrFailedToQueryByReqNmae = errors.New("failed to query environment by requested name")
