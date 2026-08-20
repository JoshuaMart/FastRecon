package config

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// AutoConfig is the --config value that opts into the user config directory.
// Without it nothing outside the explicitly given paths is read, so a
// container run never depends on what happens to be in $HOME.
const AutoConfig = "auto"

// loadFile reads a YAML config file whose keys are flag long names. It returns
// a nil map when no file applies.
func loadFile(path string) (map[string]any, string, error) {
	if path == "" {
		return nil, "", nil
	}

	resolved := path
	if path == AutoConfig {
		dir, err := os.UserConfigDir()
		if err != nil {
			return nil, "", fmt.Errorf("config auto: %w", err)
		}
		resolved = filepath.Join(dir, "fastrecon", "config.yaml")
		if _, err := os.Stat(resolved); errors.Is(err, fs.ErrNotExist) {
			// An absent auto config is the normal case, not a failure.
			return nil, "", nil
		}
	}

	data, err := os.ReadFile(resolved)
	if err != nil {
		return nil, "", fmt.Errorf("read config %s: %w", resolved, err)
	}

	var raw map[string]any
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, "", fmt.Errorf("parse config %s: %w", resolved, err)
	}
	return raw, resolved, nil
}
