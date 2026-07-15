package shellforge

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"os"
	"os/user"
	"path/filepath"
	"strings"

	"github.com/msteinert/pam"
	"golang.org/x/crypto/ssh"
)

// only supports ed25519 and *ECDSA(not implemented)
func VerifyClientSignature(filepath string, sessionID, signature, presentedPubKey []byte) (bool, error) {
	file, err := os.Open(filepath)
	if err != nil {
		return false, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.Fields(line)
		//format type key
		if len(parts) < 2 {
			continue
		}
		//comment, options, rest,
		Found_pubKey, _, _, _, err := ssh.ParseAuthorizedKey(scanner.Bytes())

		if err != nil {
			log.Printf("[auth] skipping malformed authorized_keys line: invalid: %v", err)
			continue
		}
		Found_pubKeyBytes := Found_pubKey.Marshal()

		SSH_presentedPubKey, err := ssh.NewPublicKey(ed25519.PublicKey(presentedPubKey))
		if err != nil {
			log.Printf("[auth] presented key invalid: %v", err)
			continue
		}
		SSH_presentedPubKey_bytes := SSH_presentedPubKey.Marshal()

		if !bytes.Equal(SSH_presentedPubKey_bytes, Found_pubKeyBytes) {
			log.Printf("[auth] skipping authorized_keys line presented key not egual with the key server found \n")
			continue // check the NEXT authorized key
		}

		/**********************/
		if !ed25519.Verify(presentedPubKey, sessionID, signature) {
			return false, fmt.Errorf("[auth] signature verification failed for authorized key")
		}
		return true, nil

	}

	return false, fmt.Errorf("presented public key not found in authorized keys")
}

// VerifyPKIChain validates the client's X.509 certificate against the CA pool,
// verifies the signature over the session ID, and returns the verified Common Name (Username).
func VerifyPKIChain(certDer, signature, sessionID []byte, caPool *x509.CertPool) (string, error) {
	// 1. Parse the DER-encoded X.509 certificate
	cert, err := x509.ParseCertificate(certDer)
	if err != nil {
		return "", fmt.Errorf("failed to parse client certificate: %w", err)
	}

	// 2. Verify the certificate chain against our Root CA Pool
	opts := x509.VerifyOptions{
		Roots:     caPool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, // Enforce Client Auth usage
	}
	if _, err := cert.Verify(opts); err != nil {
		return "", fmt.Errorf("certificate verification failed: %w", err)
	}

	// 3. Verify the client's signature over the Session ID
	// We extract the public key directly from the verified certificate
	switch pub := cert.PublicKey.(type) {
	case ed25519.PublicKey:
		if !ed25519.Verify(pub, sessionID, signature) {
			return "", errors.New("invalid signature (proof of key ownership failed)")
		}
	case *ecdsa.PublicKey:
		// Standard ECDSA (P-256 / P-384) verification
		// Note: In production, hash the sessionID before verifying ECDSA
		hash := sha256.Sum256(sessionID)
		if !ecdsa.VerifyASN1(pub, hash[:], signature) {
			return "", errors.New("invalid ECDSA signature")
		}
	default:
		return "", errors.New("unsupported public key algorithm in certificate")
	}

	// 4. Return the Common Name (CN) as the authenticated username!
	if cert.Subject.CommonName == "" {
		return "", errors.New("certificate missing Common Name (username)")
	}

	return cert.Subject.CommonName, nil
}

// AuthenticatePAM hands the credentials directly to the Linux PAM stack.
// It returns nil on success, or a descriptive OS auth error on failure.
func AuthenticatePAM(username, password string) error {
	// We use the "login" stack which naturally validates passwords, accounts, and lockout states.
	t, err := pam.StartFunc("login", username, func(style pam.Style, msg string) (string, error) {
		switch style {
		case pam.PromptEchoOff: // PAM is asking for the password (hide echo)
			return password, nil
		case pam.PromptEchoOn: // PAM is asking for username
			return username, nil
		}
		return "", nil
	})
	if err != nil {
		return err
	}

	// 1. Check password validity
	if err = t.Authenticate(0); err != nil {
		return err
	}

	// 2. Check account status (expired, locked, etc.)
	return t.AcctMgmt(0)
}

// UserExists checks if a specific username exists on the host Linux operating system.
// It is highly optimized, does not spawn external processes, and natively supports
// both local passwd files and enterprise directory integrations (LDAP/AD) [1.1.2].
func SysUserExists(username string) bool {
	_, err := user.Lookup(username)
	if err != nil {
		// Go's os/user package returns an UnknownUserError if the user does not exist.
		if _, ok := err.(user.UnknownUserError); ok {
			return false
		}
		// A different system/resource error occurred (e.g., temporary system memory exhaustion)
		log.Printf("[wireforge] System error looking up user %s: %v", username, err)
		return false
	}

	return true
}

func AuthorizedKeysPathForUser(username string) (string, error) {
	if username == "" ||
		strings.ContainsAny(username, `/\`) ||
		strings.Contains(username, "..") ||
		username != filepath.Base(username) {
		return "", fmt.Errorf("[auth] invalid username %q: path separators or traversal not allowed", username)
	}

	u, err := user.Lookup(username)
	if err != nil {
		return "", fmt.Errorf("[auth] user lookup failed for %q: %w", username, err)
	}
	if u.HomeDir == "" || !filepath.IsAbs(u.HomeDir) {
		return "", fmt.Errorf("[auth] user %q has no absolute home directory (got %q)", username, u.HomeDir)
	}

	return filepath.Join(u.HomeDir, ".shellforge", "authorized_keys"), nil
}
