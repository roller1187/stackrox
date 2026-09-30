package enrichment

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"golang.org/x/mod/semver"
)

type ocpVersionInfo struct {
	Current string
	Latest  string
	Channel string
}

// DetectOCPVersions auto-detects the current cluster version from the ClusterVersion API
// and queries Cincinnati for the latest available version in the same channel.
func DetectOCPVersions(ctx context.Context, logf func(string, ...interface{})) (*ocpVersionInfo, error) {
	current, channel, err := detectClusterVersion(ctx)
	if err != nil {
		return nil, fmt.Errorf("detecting cluster version: %w", err)
	}
	logf("  Auto-detected OCP cluster version: %s (channel: %s)", current, channel)

	latest, err := findLatestInChannel(ctx, channel)
	if err != nil {
		logf("  WARNING: Could not query Cincinnati for latest version: %v", err)
		logf("  Falling back to current version as target")
		return &ocpVersionInfo{Current: current, Latest: current, Channel: channel}, nil
	}

	if latest == current {
		logf("  Cluster is on the latest version in %s: %s", channel, current)
	} else {
		logf("  Latest available version in %s: %s (current: %s)", channel, latest, current)
	}

	return &ocpVersionInfo{Current: current, Latest: latest, Channel: channel}, nil
}

func detectClusterVersion(ctx context.Context) (string, string, error) {
	tokenBytes, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/token")
	if err != nil {
		return "", "", fmt.Errorf("reading service account token: %w (not running in-cluster?)", err)
	}
	token := strings.TrimSpace(string(tokenBytes))

	caPath := "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	host := os.Getenv("KUBERNETES_SERVICE_HOST")
	port := os.Getenv("KUBERNETES_SERVICE_PORT")
	if host == "" || port == "" {
		host = "kubernetes.default.svc"
		port = "443"
	}

	url := fmt.Sprintf("https://%s:%s/apis/config.openshift.io/v1/clusterversions/version", host, port)

	tlsConfig := &tls.Config{}
	if caCert, err := os.ReadFile(caPath); err == nil {
		pool, _ := x509.SystemCertPool()
		if pool == nil {
			pool = x509.NewCertPool()
		}
		pool.AppendCertsFromPEM(caCert)
		tlsConfig.RootCAs = pool
	} else {
		tlsConfig.InsecureSkipVerify = true
	}

	client := &http.Client{
		Timeout:   15 * time.Second,
		Transport: &http.Transport{TLSClientConfig: tlsConfig},
	}

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("querying ClusterVersion API: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return "", "", fmt.Errorf("ClusterVersion API returned %d: %s", resp.StatusCode, string(body))
	}

	var cv struct {
		Spec struct {
			Channel string `json:"channel"`
		} `json:"spec"`
		Status struct {
			Desired struct {
				Version string `json:"version"`
			} `json:"desired"`
			History []struct {
				State   string `json:"state"`
				Version string `json:"version"`
			} `json:"history"`
		} `json:"status"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&cv); err != nil {
		return "", "", fmt.Errorf("parsing ClusterVersion response: %w", err)
	}

	version := cv.Status.Desired.Version
	if version == "" && len(cv.Status.History) > 0 {
		version = cv.Status.History[0].Version
	}
	if version == "" {
		return "", "", fmt.Errorf("no version found in ClusterVersion resource")
	}

	channel := cv.Spec.Channel
	if channel == "" {
		parts := strings.SplitN(version, ".", 3)
		if len(parts) >= 2 {
			channel = "stable-" + parts[0] + "." + parts[1]
		}
	}

	return version, channel, nil
}

func findLatestInChannel(ctx context.Context, channel string) (string, error) {
	url := fmt.Sprintf("https://api.openshift.com/api/upgrades_info/v1/graph?channel=%s&arch=amd64", channel)

	client := &http.Client{Timeout: 15 * time.Second}
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("querying Cincinnati: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return "", fmt.Errorf("Cincinnati returned %d: %s", resp.StatusCode, string(body))
	}

	var graph struct {
		Nodes []struct {
			Version string `json:"version"`
		} `json:"nodes"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&graph); err != nil {
		return "", fmt.Errorf("parsing Cincinnati response: %w", err)
	}

	if len(graph.Nodes) == 0 {
		return "", fmt.Errorf("no versions found in channel %s", channel)
	}

	versions := make([]string, 0, len(graph.Nodes))
	for _, n := range graph.Nodes {
		if n.Version != "" {
			versions = append(versions, n.Version)
		}
	}

	sort.Slice(versions, func(i, j int) bool {
		vi := "v" + versions[i]
		vj := "v" + versions[j]
		return semver.Compare(vi, vj) > 0
	})

	if len(versions) == 0 {
		return "", fmt.Errorf("no valid versions in channel %s", channel)
	}

	return versions[0], nil
}
