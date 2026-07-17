package main

import (
	"log"
	"os"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/the-mhdi/shellforge/shellforge" // Preserved your custom module import
	cli "github.com/urfave/cli/v2"
)

const DAEMON_CONFIG_FILE_DEFAULT string = "/etc/shellforge/config"

// TOMLDaemonConfig represents the fields inside your daemon config TOML file
type TOMLDaemonConfig struct {
	AcceptedInitMsgs                []string `toml:"AcceptedInitMsgs"`
	DaemonInitMsg                   string   `toml:"DaemonInitMsg"`
	ListenAddr                      string   `toml:"ListenAddr"`
	Port                            string   `toml:"Port"` // default 77
	PasswordAuth                    bool     `toml:"PasswordAuth"`
	PublicKeyAuth                   bool     `toml:"PublicKeyAuth"`
	AuthorizedKeysPath              string   `toml:"AuthorizedKeysPath"`
	AllowLoginAsRoot                bool     `toml:"AllowLoginAsRoot"`
	MaxConnectionsAllowed           uint32   `toml:"MaxConnectionsAllowed"`
	MaxContainersConnectionsAllowed uint32   `toml:"MaxContainersConnectionsAllowed"`
	DatabaseDirectory               string   `toml:"DatabaseDirectory"`
	HostKeyPath                     string   `toml:"HostKeyPath"`
}

// LoadDaemonConfig reads the TOML file from disk and parses it [1, 2]
func LoadDaemonConfig(path string) (*TOMLDaemonConfig, error) {
	bytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	cfg := &TOMLDaemonConfig{}
	if err := toml.Unmarshal(bytes, cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

func main() {
	// Build the standalone daemon CLI application
	app := &cli.App{
		Name:  "daemon",
		Usage: "shellforge Standalone Daemon Service",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "listen",
				Aliases: []string{"l"},
				Usage:   "TCP listen address (e.g., 0.0.0.0:77)",
			},
			&cli.StringFlag{
				Name:    "config",
				Aliases: []string{"c"},
				Usage:   "Path to a daemon configuration TOML file",
			},
		},
		Action: func(cCtx *cli.Context) error {
			cliListen := cCtx.String("listen")
			configPath := cCtx.String("config")

			// 1. Resolve and merge configurations dynamically [1, 2, 3]
			runDaemon(cliListen, configPath)
			return nil
		},
	}

	// Execute the application [cli1]
	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}

func runDaemon(listenAddr, configPath string) {

	// 4. defalut Construct the final shellforge.DaemonConfig
	conf := shellforge.DaemonConfig{
		AcceptedInitMsgs: []string{"SHELLFORGE-v0.1.0"},
		DaemonInitMsg:    "SHELLFORGE-v0.1.0",
		ListenAddr:       "0.0.0.0",
		Port:             "77",
		PasswordAuth:     true,
		PublicKeyAuth:    true,
		AllowLoginAsRoot: true,
		HandshakeTimeout: 30 * time.Second,
		//IdleTimeout:                     30 * time.Minute,
		AuthorizedKeysPath:              "",
		MaxConnectionsAllowed:           0,
		MaxContainersConnectionsAllowed: 0,
		ClientInitHandler:               nil,
	}

	if configPath == "" {
		configPath = DAEMON_CONFIG_FILE_DEFAULT
	}

	log.Printf("[Daemon] Loading configuration file: %s", configPath)

	tomlConfig, err := LoadDaemonConfig(configPath)
	if err != nil {
		log.Printf("failed to load config file: %v", err)
		//return
	}

	// If the TOML config was successfully loaded, overwrite the defaults [1]
	if tomlConfig != nil {
		if len(tomlConfig.AcceptedInitMsgs) > 0 {
			conf.AcceptedInitMsgs = tomlConfig.AcceptedInitMsgs
		}
		if tomlConfig.DaemonInitMsg != "" {
			conf.DaemonInitMsg = tomlConfig.DaemonInitMsg
		}
		conf.PasswordAuth = tomlConfig.PasswordAuth
		conf.PublicKeyAuth = tomlConfig.PublicKeyAuth
		conf.AllowLoginAsRoot = tomlConfig.AllowLoginAsRoot

		if tomlConfig.AuthorizedKeysPath != "" {
			conf.AuthorizedKeysPath = tomlConfig.AuthorizedKeysPath
		}
		if tomlConfig.ListenAddr != "" {
			conf.ListenAddr = tomlConfig.ListenAddr
		}
		if tomlConfig.Port != "" {
			conf.Port = tomlConfig.Port
		}

		if tomlConfig.MaxConnectionsAllowed != 0 {
			conf.MaxConnectionsAllowed = tomlConfig.MaxConnectionsAllowed
		}

		if tomlConfig.MaxContainersConnectionsAllowed != 0 {
			conf.MaxConnectionsAllowed = tomlConfig.MaxConnectionsAllowed
		}

		if tomlConfig.DatabaseDirectory != "" {
			conf.DatabaseDir = tomlConfig.DatabaseDirectory
		}
		// Map additional fields from your TOML config...
	}

	if listenAddr != "" {
		s := strings.Split(listenAddr, ":")
		if s[0] != "" {
			conf.ListenAddr = s[0]
		}

		if s[1] != "" {
			conf.Port = s[1]
		}
	}

	shellforge.Start(conf)
}
