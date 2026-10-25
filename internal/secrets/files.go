package secrets

import (
	"context"
	"fmt"
	"io"
	"os"
)

// maxFileBytes caps one secret file. A token is well under a kilobyte; a file
// larger than this was mounted from the wrong key.
const maxFileBytes = 64 << 10

// Files is a Getter whose names are file paths: the Kubernetes counterpart of
// SSM, a Secret mounted as a volume. Each Get re-reads the files, so with a
// Cache over it an invalidated token is picked up from the file the kubelet
// has already refreshed after a rotation, with no restart.
//
// Errors name the path and never the content.
type Files struct{}

var _ Getter = Files{}

// Get reads every named file. Any file that cannot be read fails the call.
func (Files) Get(_ context.Context, names ...string) (map[string]string, error) {
	out := make(map[string]string, len(names))
	for _, name := range names {
		v, err := readFile(name)
		if err != nil {
			return nil, err
		}
		out[name] = v
	}
	return out, nil
}

func readFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("opening secret file: %w", err)
	}
	defer f.Close()

	raw, err := io.ReadAll(io.LimitReader(f, maxFileBytes+1))
	if err != nil {
		return "", fmt.Errorf("reading secret file %s: %w", path, err)
	}
	if len(raw) > maxFileBytes {
		return "", fmt.Errorf("secret file %s is larger than %d bytes", path, maxFileBytes)
	}
	return string(raw), nil
}
