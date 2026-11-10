package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// --- file backend --------------------------------------------------------------
//
// A JSON object mapping secret path -> secret object. For demos and tests
// without Vault. The file should be mode 0600; secretsd warns if it is not.

type fileBackend struct {
	secrets map[string]map[string]any
}

func newFileBackend(path string) (*fileBackend, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if st.Mode().Perm()&0o077 != 0 {
		fmt.Fprintf(os.Stderr, "secretsd: WARNING: %s is readable by others (mode %o); chmod 600 it\n", path, st.Mode().Perm())
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var m map[string]map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("secrets file: %w", err)
	}
	return &fileBackend{secrets: m}, nil
}

func (f *fileBackend) Get(path string) (map[string]any, error) {
	s, ok := f.secrets[path]
	if !ok {
		return nil, errors.New("no such secret path")
	}
	return s, nil
}

// --- vault backend ------------------------------------------------------------
//
// AppRole login, then KV v2 reads. Standard library HTTP only. The AppRole
// secret id comes from the environment so it is not on the command line.
// Tokens are renewed by re-logging-in when a read returns 403.

type vaultBackend struct {
	addr, mount, roleID, secretID string
	client                        *http.Client

	mu    sync.Mutex
	token string
}

func newVaultBackend(addr, mount, roleID, secretID string) (*vaultBackend, error) {
	if roleID == "" || secretID == "" {
		return nil, errors.New("vault: -vault-role-id and VAULT_SECRET_ID are required")
	}
	v := &vaultBackend{
		addr: strings.TrimRight(addr, "/"), mount: mount, roleID: roleID, secretID: secretID,
		client: &http.Client{Timeout: 5 * time.Second},
	}
	if err := v.login(); err != nil {
		return nil, err
	}
	return v, nil
}

func (v *vaultBackend) login() error {
	body, _ := json.Marshal(map[string]string{"role_id": v.roleID, "secret_id": v.secretID})
	resp, err := v.client.Post(v.addr+"/v1/auth/approle/login", "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("vault login: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("vault login: %s: %s", resp.Status, strings.TrimSpace(string(b)))
	}
	var out struct {
		Auth struct {
			ClientToken string `json:"client_token"`
		} `json:"auth"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil || out.Auth.ClientToken == "" {
		return errors.New("vault login: no client token in response")
	}
	v.mu.Lock()
	v.token = out.Auth.ClientToken
	v.mu.Unlock()
	return nil
}

func (v *vaultBackend) Get(path string) (map[string]any, error) {
	for attempt := 0; attempt < 2; attempt++ {
		v.mu.Lock()
		tok := v.token
		v.mu.Unlock()

		// KV v2: /v1/<mount>/data/<path>
		req, _ := http.NewRequest("GET", fmt.Sprintf("%s/v1/%s/data/%s", v.addr, v.mount, strings.TrimLeft(path, "/")), nil)
		req.Header.Set("X-Vault-Token", tok)
		resp, err := v.client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("vault read: %w", err)
		}
		if resp.StatusCode == 403 && attempt == 0 {
			resp.Body.Close()
			if err := v.login(); err != nil {
				return nil, err
			}
			continue
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			return nil, fmt.Errorf("vault read: %s", resp.Status)
		}
		var out struct {
			Data struct {
				Data map[string]any `json:"data"`
			} `json:"data"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
			return nil, fmt.Errorf("vault read: decode: %w", err)
		}
		return out.Data.Data, nil
	}
	return nil, errors.New("vault read: unreachable")
}
