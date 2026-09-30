package enrichment

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	cveatypes "github.com/stackrox/rox/central/cveanalyzer/types"
)

// ResolveManifestListDigests replaces architecture-specific digests in FixLatestRef
// with manifest list digests for accurate Red Hat Catalog URL linking.
func ResolveManifestListDigests(ctx context.Context, records []cveatypes.CVERecord, logf func(string, ...interface{})) {
	type refInfo struct {
		base string
		tag  string
	}

	uniqueRefs := make(map[string]*refInfo)
	for _, r := range records {
		ref := r.FixLatestRef
		if ref == "" || !strings.Contains(ref, "@") {
			continue
		}
		if strings.Contains(ref, "ocp-v4.0-art-dev") || strings.Contains(ref, "ocp-release") {
			continue
		}

		base := ref
		if idx := strings.Index(base, "@"); idx >= 0 {
			base = base[:idx]
		}
		tag := r.FixLatestTag
		if tag == "" || tag == "latest" {
			continue
		}
		uniqueRefs[base] = &refInfo{base: base, tag: tag}
	}

	if len(uniqueRefs) == 0 {
		logf("  No images eligible for manifest list resolution")
		return
	}

	logf("  Resolving manifest list digests for %d images", len(uniqueRefs))

	type mlResult struct {
		digest string
		err    string
	}

	cache := make(map[string]*mlResult)
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)

	for _, info := range uniqueRefs {
		wg.Add(1)
		sem <- struct{}{}
		go func(base, tag string) {
			defer wg.Done()
			defer func() { <-sem }()

			digest, errStr := fetchManifestListDigest(ctx, base, tag)
			mu.Lock()
			cache[base] = &mlResult{digest: digest, err: errStr}
			mu.Unlock()
		}(info.base, info.tag)
	}
	wg.Wait()

	found := 0
	singleArch := 0
	errors := 0
	for _, r := range cache {
		if r.digest != "" {
			found++
		} else if r.err == "single-arch" {
			singleArch++
		} else {
			errors++
		}
	}

	logf("  Manifest list: %d multi-arch, %d single-arch, %d errors", found, singleArch, errors)

	updated := 0
	for i := range records {
		r := &records[i]
		ref := r.FixLatestRef
		if ref == "" || !strings.Contains(ref, "@") {
			continue
		}
		base := ref
		if idx := strings.Index(base, "@"); idx >= 0 {
			base = base[:idx]
		}
		result, ok := cache[base]
		if !ok || result.digest == "" {
			continue
		}
		r.FixLatestRef = base + "@" + result.digest
		updated++
	}

	logf("  Updated %d records with manifest list digests", updated)
}

func fetchManifestListDigest(ctx context.Context, base, tag string) (string, string) {
	registry, repo := splitRegistryRepo(base)
	if registry == "" || repo == "" {
		return "", "parse error"
	}

	url := fmt.Sprintf("https://%s/v2/%s/manifests/%s", registry, repo, tag)
	client := &http.Client{Timeout: 30 * time.Second}

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", err.Error()
	}
	req.Header.Set("Accept", strings.Join([]string{
		"application/vnd.docker.distribution.manifest.list.v2+json",
		"application/vnd.oci.image.index.v1+json",
		"application/vnd.docker.distribution.manifest.v2+json",
		"application/vnd.oci.image.manifest.v1+json",
	}, ", "))

	if registry == "quay.io" {
		if token, err := fetchQuayToken(registry, repo); err == nil && token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
	} else if registry == "registry.redhat.io" || registry == "registry.access.redhat.com" {
		if token, err := fetchRedHatToken(registry, repo); err == nil && token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", err.Error()
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", fmt.Sprintf("HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))
	if err != nil {
		return "", err.Error()
	}

	contentType := resp.Header.Get("Content-Type")
	if strings.Contains(contentType, "manifest.list") || strings.Contains(contentType, "image.index") {
		hash := sha256.Sum256(body)
		return fmt.Sprintf("sha256:%x", hash), ""
	}

	var parsed struct {
		MediaType string `json:"mediaType"`
	}
	if json.Unmarshal(body, &parsed) == nil {
		if strings.Contains(parsed.MediaType, "manifest.list") || strings.Contains(parsed.MediaType, "image.index") {
			hash := sha256.Sum256(body)
			return fmt.Sprintf("sha256:%x", hash), ""
		}
	}

	return "", "single-arch"
}

func fetchRedHatToken(registry, repo string) (string, error) {
	url := fmt.Sprintf("https://sso.redhat.com/auth/realms/rhcc/protocol/docker-v2/auth?service=%s&scope=repository:%s:pull", registry, repo)
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("auth returned %d", resp.StatusCode)
	}

	var tokenResp struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", err
	}
	if tokenResp.Token != "" {
		return tokenResp.Token, nil
	}
	return tokenResp.AccessToken, nil
}

func splitRegistryRepo(base string) (string, string) {
	parts := strings.SplitN(base, "/", 2)
	if len(parts) < 2 {
		return "", ""
	}
	if !strings.Contains(parts[0], ".") {
		return "", ""
	}
	return parts[0], parts[1]
}
