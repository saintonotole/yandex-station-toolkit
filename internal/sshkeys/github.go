package sshkeys

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

func FetchGitHubKeys(ctx context.Context, user string) ([]PubKey, error) {
	user = strings.TrimSpace(user)
	if user == "" {
		return nil, nil
	}
	if strings.ContainsAny(user, "/ \t\n\r") {
		return nil, fmt.Errorf("GitHub username contains invalid characters")
	}
	url := "https://github.com/" + user + ".keys"
	hc := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "YandexStationToolKit")
	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("github: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == 404 {
		return nil, fmt.Errorf("GitHub user %q was not found", user)
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("github: HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	keys := ParseDeviceAuthorizedKeys(string(body))
	if len(keys) == 0 {
		return nil, fmt.Errorf("GitHub user %q has no published SSH keys", user)
	}
	return keys, nil
}
