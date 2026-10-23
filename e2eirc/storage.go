package e2eirc

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
)

const (
	filePerms = 0o600
	dirPerms  = 0o700

	identityFile = "identity.key"
	registryFile = "trusted_keys"
)

// dirPath returns the data directory, creating it with 0700 if needed.
func dirPath() (string, error) {
	path := sharedConfig.dirPath
	if path == "" {
		usr, err := user.Current()
		if err != nil {
			return "", fmt.Errorf("determine home directory: %w", err)
		}
		path = filepath.Join(usr.HomeDir, ".e2eirc")
	}
	if err := os.MkdirAll(path, dirPerms); err != nil {
		return "", fmt.Errorf("create %s: %w", path, err)
	}
	return path, nil
}

func dataFile(name string) (string, error) {
	dir, err := dirPath()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, name), nil
}

// writeFileAtomic writes data to a temporary file in the same directory
// with mode 0600 and renames it into place, so a crash never leaves a
// truncated key or registry file behind.
func writeFileAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := func(err error) error {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Chmod(filePerms); err != nil {
		return cleanup(err)
	}
	if _, err := tmp.Write(data); err != nil {
		return cleanup(err)
	}
	if err := tmp.Sync(); err != nil {
		return cleanup(err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		os.Remove(tmpName)
		return err
	}
	return nil
}
