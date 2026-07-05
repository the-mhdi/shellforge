package main

import (
	"encoding/json"
	"log"
	"os"
	"strings"

	"github.com/the-mhdi/shellforge/shellforge" // Preserved your custom module import
	cli "github.com/urfave/cli/v2"
)

// JSONDaemonConfig represents the fields inside your daemon config JSON file
type JSONDaemonConfig struct {
	AcceptedInitMsgs                []string `json:"AcceptedInitMsgs"`
	DaemonInitMsg                   string   `json:"DaemonInitMsg"`
	ListenAddr                      string   `json:"ListenAddr"`
	Port                            string   `json:"Port"` // default 77
	PasswordAuth                    bool     `json:"PasswordAuth"`
	PublicKeyAuth                   bool     `json:"PublicKeyAuth"`
	AuthorizedKeysPath              string   `json:"AuthorizedKeysPath"`
	AllowLoginAsRoot                bool     `json:"AllowLoginAsRoot"`
	MaxConnectionsAllowed           uint32   `json:"MaxConnectionsAllowed"`
	MaxContainersConnectionsAllowed uint32   `json:"MaxContainersConnectionsAllowed"`
	EnvironmentsJsonConfig          string   `json:"EnvironmentsJsonConfig"`
	DatabaseDirectory               string   `json:"DatabaseDirectory"`
	HostKeyPath                     string   `json:"HostKeyPath"`
}

// LoadDaemonConfig reads the JSON file from disk and parses it [1, 2]
func LoadDaemonConfig(path string) (*JSONDaemonConfig, error) {
	bytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	cfg := &JSONDaemonConfig{}
	if err := json.Unmarshal(bytes, cfg); err != nil {
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
				Name:    "envsConf",
				Aliases: []string{"ec"},
				Usage:   "Path to the environments configuration JSON file",
			},
			&cli.StringFlag{
				Name:    "config",
				Aliases: []string{"c"},
				Usage:   "Path to a daemon configuration JSON file",
			},
		},
		Action: func(cCtx *cli.Context) error {
			cliListen := cCtx.String("listen")
			cliEnvs := cCtx.String("envsConf")
			configPath := cCtx.String("config")

			// 1. Resolve and merge configurations dynamically [1, 2, 3]
			runDaemon(cliListen, cliEnvs, configPath)
			return nil
		},
	}

	// Execute the application [cli1]
	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}

func runDaemon(listenAddr, ENVsJsonConfDir, configPath string) {

	// 4. defalut Construct the final shellforge.DaemonConfig
	conf := shellforge.DaemonConfig{
		AcceptedInitMsgs:                []string{"WIREFORGE-1.0"},
		DaemonInitMsg:                   "WIREFORGE-1.0",
		ListenAddr:                      "0.0.0.0",
		Port:                            "77",
		PasswordAuth:                    true,
		PublicKeyAuth:                   true,
		AllowLoginAsRoot:                true,
		AuthorizedKeysPath:              "",
		MaxConnectionsAllowed:           0,
		MaxContainersConnectionsAllowed: 0,
		EnvironmentsJsonConfig:          "",
		ClientInitHandler:               nil,
	}

	if configPath == "" {
		configPath = "/etc/shellforge/config.json"
	}

	log.Printf("[Daemon] Loading configuration file: %s", configPath)

	jsonConfig, err := LoadDaemonConfig(configPath)
	if err != nil {
		log.Printf("failed to load config file: %v", err)
		return
	}

	// If the JSON config was successfully loaded, overwrite the defaults [1]
	if jsonConfig != nil {
		if len(jsonConfig.AcceptedInitMsgs) > 0 {
			conf.AcceptedInitMsgs = jsonConfig.AcceptedInitMsgs
		}
		if jsonConfig.DaemonInitMsg != "" {
			conf.DaemonInitMsg = jsonConfig.DaemonInitMsg
		}
		conf.PasswordAuth = jsonConfig.PasswordAuth
		conf.PublicKeyAuth = jsonConfig.PublicKeyAuth
		conf.AllowLoginAsRoot = jsonConfig.AllowLoginAsRoot

		if jsonConfig.AuthorizedKeysPath != "" {
			conf.AuthorizedKeysPath = jsonConfig.AuthorizedKeysPath
		}
		if jsonConfig.ListenAddr != "" {
			conf.ListenAddr = jsonConfig.ListenAddr
		}
		if jsonConfig.Port != "" {
			conf.Port = jsonConfig.Port
		}

		if jsonConfig.MaxConnectionsAllowed != 0 {
			conf.MaxConnectionsAllowed = jsonConfig.MaxConnectionsAllowed
		}

		if jsonConfig.MaxContainersConnectionsAllowed != 0 {
			conf.MaxConnectionsAllowed = jsonConfig.MaxConnectionsAllowed
		}

		if jsonConfig.EnvironmentsJsonConfig != "" {
			conf.EnvironmentsJsonConfig = jsonConfig.EnvironmentsJsonConfig
		}

		if jsonConfig.DatabaseDirectory != "" {
			conf.DatabaseDir = jsonConfig.DatabaseDirectory
		}
		// Map additional fields from your JSON config...
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

	conf.EnvironmentsJsonConfig = ENVsJsonConfDir

	shellforge.Start(conf)
}
