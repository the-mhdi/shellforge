package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/the-mhdi/shellforge/shellforge" // Replace with your actual module path
)

// =====================================================================
// Supported invocations:
//
//   ./client -c [configdir] username@ip[:port] -L[] -R[] -D[]
//   ./client container containerName@ip:port -c [configdir]
//   ./client containers ip:port -c [configdir]
//   ./client make container|system-user name requestedName -c [configdir] ip:port
//
// -c / --config can appear ANYWHERE in the argument list (before, after,
// or between other args/flags) in every mode. It points at a config
// DIRECTORY, assumed to contain:
//   <configdir>/id_ed25519   - private key (overrides ~/.shellforge, ~/.ssh)
//   <configdir>/config.json  - optional JSON overrides (same fields as before)
// If -c is omitted, defaults to ~/.shellforge, falling back to ~/.ssh for
// the key if ~/.shellforge/id_ed25519 doesn't exist.
//
// OTHER ASSUMPTIONS (flag these if wrong):
//   1. In "make", the literal word "name" is a required keyword before
//      the requested-name value, per the bracket spec you gave.
//   2. shellforge.Client has ListContainers(crypto.Signer) ([]string, error)
//      — adjust if the real signature differs.
//   3. -D (dynamic/SOCKS5 forwarding) remains a logged TODO stub.
// =====================================================================

type JSONClientConfig struct {
	PreferedKeyExAlgo       string `json:"PreferedKeyExAlgo"`
	PreferedEncyptionCipher string `json:"PreferedEncyptionCipher"`
	ClientInitMessage       string `json:"ClientInitMessage"`
}

func main() {
	configOverride, args, err := extractFlagValue(os.Args[1:], "-c", "--config")
	if err != nil {
		log.Fatal(err)
	}
	if len(args) < 1 {
		printUsage()
		os.Exit(1)
	}
	ctx := context.Background()
	switch args[0] {
	case "container":
		err = runContainerMode(ctx, args[1:], configOverride)
	case "containers":
		err = runContainersMode(ctx, args[1:], configOverride)
	case "make":
		err = runMakeMode(ctx, args[1:], configOverride)
	default:
		err = runDefaultMode(ctx, args, configOverride)
	}

	if err != nil {
		log.Fatal(err)
	}
	quit := make(chan os.Signal, 1)
	// // Catch Ctrl+C (SIGINT) and Docker/K8s stop (SIGTERM)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
	select {
	case <-quit:

		log.Printf(" SIGTERM CAUGHT")

	case <-ctx.Done():

		log.Printf("Shutting down gracefully")

	}
}

// ---------------------------------------------------------------------
// Mode: ./client container containerName@ip:port [-c configdir]
// ---------------------------------------------------------------------
func runContainerMode(ctx context.Context, args []string, configOverride string) error {
	if len(args) != 1 {
		return errors.New("usage: client container <containerName>@<ip:port> [-c configdir]")
	}
	name, hostport, err := parseNameAtHostPort(args[0])
	if err != nil {
		return err
	}

	client, err := newClient(ctx, hostport, configOverride)
	if err != nil {
		return err
	}

	if err := client.ConnectWithNoAuth(ctx); err != nil {
		return err
	}
	configDir := resolveConfigDir(configOverride)
	signers, err := shellforge.LoadKeys(configDir, true)

	if err != nil {
		return err

	}
	primary := signers[0]

	log.Printf("[CLI] Querying and running container: %s", name)
	return client.GetAndRunContainer(name, primary)
}

// ---------------------------------------------------------------------
// Mode: ./client containers ip:port [-c configdir]
// ---------------------------------------------------------------------
func runContainersMode(ctx context.Context, args []string, configOverride string) error {
	if len(args) != 1 {
		return errors.New("usage: client containers <ip:port> [-c configdir]")
	}
	hostport := withDefaultPort(args[0])

	client, err := newClient(ctx, hostport, configOverride)
	if err != nil {
		return err
	}
	//ctx := context.Background()

	if err := client.ConnectWithNoAuth(ctx); err != nil {
		return err
	}
	configDir := resolveConfigDir(configOverride)
	signers, err := shellforge.LoadKeys(configDir, true)

	if err != nil {
		return err

	}
	primary := signers[0]

	// ASSUMPTION: adjust this call if your shellforge.Client method for
	// listing containers has a different name/signature.
	err = client.GetAndRunContainer("", primary)
	if err != nil {
		return err
	}
	return nil
}

// ---------------------------------------------------------------------
// Mode: ./client make container|system-user name requestedName [-c configdir] ip:port
// ---------------------------------------------------------------------
func runMakeMode(ctx context.Context, args []string, configOverride string) error {
	if len(args) != 4 || args[1] != "name" {
		return errors.New("usage: client make <container|system-user> name <requested-name> [-c configdir] <ip:port>")
	}
	envType := args[0]
	requestedName := args[2]
	hostport := withDefaultPort(args[3])

	if envType != "container" && envType != "system-user" && envType != "hostsharednamespace" {
		return fmt.Errorf("unsupported env type %q", envType)
	}

	client, err := newClient(ctx, hostport, configOverride)
	if err != nil {
		return err
	}
	//ctx := context.Background()

	if err := client.ConnectWithNoAuth(ctx); err != nil {
		return err
	}
	log.Printf("[CLI] Pre-creating %s environment named %s...", envType, requestedName)

	configDir := resolveConfigDir(configOverride)
	signers, err := shellforge.LoadKeys(configDir, true)

	if err != nil {
		return err

	}
	primary := signers[0]
	return client.CreateENV(envType, requestedName, primary)
}

// ---------------------------------------------------------------------
// Mode: ./client [-c configdir] username@ip[:port] -L[...] -R[...] -D[...]
// ---------------------------------------------------------------------
func runDefaultMode(ctx context.Context, args []string, configOverride string) error {
	user, hostport, err := parseUserHost(args[0])
	if err != nil {
		return err
	}

	// args[0] is the positional user@host; everything after it is flags.
	// Stripping the positional ourselves means flag.Parse never has to
	// "stop at the first non-flag arg" — it only ever sees flags.
	fs := flag.NewFlagSet("client", flag.ExitOnError)
	var localFwds, remoteFwds multiFlag
	var dynamicFwd string
	fs.Var(&localFwds, "L", "local port forward local_port:remote_ip:remote_port (repeatable)")
	fs.Var(&remoteFwds, "R", "remote port forward remote_port:local_ip:local_port (repeatable)")
	fs.StringVar(&dynamicFwd, "D", "", "dynamic SOCKS5 forward port")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}

	client, err := newClient(ctx, hostport, configOverride)
	if err != nil {
		return err
	}
	//ctx := context.Background()

	hasForwards := len(localFwds) > 0 || len(remoteFwds) > 0 || dynamicFwd != ""

	if hasForwards {
		for _, f := range localFwds {
			local, remote, err := parseForwardingString(f)
			if err != nil {
				return err
			}
			if err := client.Connect(ctx, user); err != nil {
				return err
			}
			log.Printf("[CLI] Local forward (-L): %s -> %s", local, remote)
			go client.ForwardLocalToRemote(ctx, local, remote)
		}
		for _, f := range remoteFwds {
			remote, local, err := parseForwardingString(f)
			if err != nil {
				return err
			}
			if err := client.Connect(ctx, user); err != nil {
				return err
			}
			log.Printf("[CLI] Remote forward (-R): %s -> %s", remote, local)
			if err := client.ForwardRemoteToLocal(remote, local); err != nil {
				return err
			}
		}
		if dynamicFwd != "" {
			// TODO: wire up SOCKS5 dynamic forwarding implementation.
			log.Printf("[CLI] Dynamic forward (-D) on port %s requested (not yet implemented)", dynamicFwd)
		}
		select {} // keep tunnels alive
	}

	log.Println("[CLI] Launching interactive shell...")
	if err := client.Connect(ctx, user); err != nil {
		return err
	}
	return client.RequestShell("/bin/bash", user)
}

// ---------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------

// extractFlagValue scans args for any of the given flag names (supporting
// both "-c value" and "-c=value" forms), wherever they appear, and returns
// the found value plus the remaining args with that flag/value removed.
func extractFlagValue(args []string, names ...string) (value string, rest []string, err error) {
	rest = make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		a := args[i]
		matched := false
		for _, n := range names {
			if a == n {
				if i+1 >= len(args) {
					return "", nil, fmt.Errorf("%s requires a value", n)
				}
				value = args[i+1]
				i++
				matched = true
				break
			}
			if strings.HasPrefix(a, n+"=") {
				value = strings.TrimPrefix(a, n+"=")
				matched = true
				break
			}
		}
		if !matched {
			rest = append(rest, a)
		}
	}
	return value, rest, nil
}

// multiFlag implements flag.Value so -L/-R can be passed multiple times.
type multiFlag []string

func (m *multiFlag) String() string { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error {
	*m = append(*m, v)
	return nil
}

// parseUserHost parses "username@ip[:port]" or just "ip[:port]".
func parseUserHost(s string) (user, hostport string, err error) {
	parts := strings.SplitN(s, "@", 2)
	if len(parts) == 2 {
		user, hostport = parts[0], parts[1]
	} else {
		hostport = parts[0]
	}
	if hostport == "" {
		return "", "", fmt.Errorf("missing host in %q", s)
	}
	return user, withDefaultPort(hostport), nil
}

// parseNameAtHostPort parses "name@ip:port" (used by "container" mode).
func parseNameAtHostPort(s string) (name, hostport string, err error) {
	parts := strings.SplitN(s, "@", 2)
	if len(parts) != 2 {
		return "", "", fmt.Errorf("expected name@ip:port, got %q", s)
	}
	return parts[0], withDefaultPort(parts[1]), nil
}

func withDefaultPort(hostport string) string {
	if !strings.Contains(hostport, ":") {
		return hostport + ":77"
	}
	return hostport
}

func parseForwardingString(s string) (local, remote string, err error) {
	parts := strings.Split(s, ":")
	switch len(parts) {
	case 3:
		// "8080:10.0.0.5:3306" -> "127.0.0.1:8080", "10.0.0.5:3306"
		return "127.0.0.1:" + parts[0], parts[1] + ":" + parts[2], nil
	case 2:
		// "8080:80" -> "127.0.0.1:8080", "127.0.0.1:80"
		return "127.0.0.1:" + parts[0], "127.0.0.1:" + parts[1], nil
	default:
		return "", "", fmt.Errorf("invalid forwarding format %q (must be local_port:remote_ip:remote_port)", s)
	}
}

// resolveConfigDir returns the override directory if given, otherwise
// defaults to ~/.shellforge.
func resolveConfigDir(override string) string {
	if override != "" {
		return override
	}
	return os.Getenv("HOME") + "/.shellforge"
}

// newClient resolves the config directory, loads the private key and
// JSON config overrides, builds the shellforge.ClientConfig (including
// the PrivateKey field your Connect() relies on), and constructs the client.
func newClient(ctx context.Context, hostport, configOverride string) (*shellforge.Client, error) {
	configDir := resolveConfigDir(configOverride)

	conf, err := buildConfig(configDir)
	client := shellforge.NewClient(ctx, hostport, conf)
	if err != nil {
		log.Printf("[ERROR] faild to load config file")
		client = shellforge.NewClient(ctx, hostport, nil)
	}

	return client, nil
}

// buildConfig builds the ClientConfig with defaults, then applies overrides
// from <configDir>/config.json if it exists.
func buildConfig(configDir string) (*shellforge.ClientConfig, error) {
	conf := &shellforge.ClientConfig{
		PreferedKeyExAlgo:       "hybrid-x25519-mlkem768", // Default to high-security PQC
		PreferedEncyptionCipher: "chacha20-poly1305",
		ClientInitMessage:       "SHELLFORGE-v0.1.0",
	}

	jsonPath := configDir
	if _, err := os.Stat(jsonPath); err == nil {
		log.Printf("[client] Loading configuration file: %s", jsonPath)
		jcc, err := loadJSONClientConfig(jsonPath)
		if err != nil {
			return nil, err
		}
		if jcc.ClientInitMessage != "" {
			conf.ClientInitMessage = jcc.ClientInitMessage
		}
		if jcc.PreferedKeyExAlgo != "" {
			conf.PreferedKeyExAlgo = jcc.PreferedKeyExAlgo
		}
		if jcc.PreferedEncyptionCipher != "" {
			conf.PreferedEncyptionCipher = jcc.PreferedEncyptionCipher
		}
	}
	return conf, nil
}

func loadJSONClientConfig(path string) (*JSONClientConfig, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cfg := &JSONClientConfig{}
	if err := json.Unmarshal(raw, cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

func printUsage() {
	fmt.Println("Wireforge Client Utility (client)")
	fmt.Println("Usage:")
	fmt.Println("  client [-c configdir] username@ip[:port] [-L local:remote] [-R remote:local] [-D port]")
	fmt.Println("  client container containerName@ip:port [-c configdir]")
	fmt.Println("  client containers ip:port [-c configdir]")
	fmt.Println("  client make container|system-user name requestedName [-c configdir] ip:port")
}
