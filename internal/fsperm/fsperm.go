package fsperm

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

var ErrNotPrivate = errors.New("directory is not private")

var restrictDir = restrict

func PrivateDir(dir string) error {
	dir = filepath.Clean(dir)
	missing, err := missingDirs(dir)
	if err != nil {
		return err
	}
	if len(missing) == 0 {
		return checkExisting(dir)
	}

	var made []string
	undo := func() {
		for i := len(made) - 1; i >= 0; i-- {
			_ = os.Remove(made[i])
		}
	}
	for _, d := range missing {
		if err := os.Mkdir(d, 0o700); err != nil {
			if errors.Is(err, fs.ErrExist) {

				if cerr := checkExisting(d); cerr != nil {
					undo()
					return cerr
				}
				continue
			}
			undo()
			return err
		}
		made = append(made, d)
		if err := restrictDir(d); err != nil {
			undo()
			return err
		}
	}
	return nil
}

func missingDirs(dir string) ([]string, error) {
	var missing []string
	for d := dir; ; {
		st, err := os.Stat(d)
		if err == nil {
			if !st.IsDir() {
				return nil, fmt.Errorf("fsperm: %s exists and is not a directory", d)
			}
			break
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}
		missing = append(missing, d)
		parent := filepath.Dir(d)
		if parent == d {
			break
		}
		d = parent
	}
	for i, j := 0, len(missing)-1; i < j; i, j = i+1, j-1 {
		missing[i], missing[j] = missing[j], missing[i]
	}
	return missing, nil
}
