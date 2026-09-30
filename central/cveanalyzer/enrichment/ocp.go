package enrichment

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	cveatypes "github.com/stackrox/rox/central/cveanalyzer/types"
	imageEnricher "github.com/stackrox/rox/pkg/images/enricher"
	"github.com/stackrox/rox/pkg/sac"
)

type ocpComponentMap struct {
	components map[string]string // component name -> image ref
	digestMap  map[string]string // current digest -> target ref
}

func extractOCPPayload(targetVersion string) (*ocpComponentMap, error) {
	releaseRef := fmt.Sprintf("quay.io/openshift-release-dev/ocp-release:%s-x86_64", targetVersion)

	manifest, err := fetchRegistryManifest("quay.io", "openshift-release-dev/ocp-release", targetVersion+"-x86_64")
	if err != nil {
		return nil, fmt.Errorf("fetching release manifest: %w", err)
	}

	configDigest := manifest.Config.Digest
	if configDigest == "" {
		return nil, fmt.Errorf("no config digest in release manifest")
	}

	configBlob, err := fetchRegistryBlob("quay.io", "openshift-release-dev/ocp-release", configDigest)
	if err != nil {
		return nil, fmt.Errorf("fetching config blob: %w", err)
	}

	var config struct {
		Config struct {
			Labels map[string]string `json:"Labels"`
		} `json:"config"`
	}
	if err := json.Unmarshal(configBlob, &config); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}

	refData := config.Config.Labels["io.openshift.release"]
	if refData == "" {
		return nil, extractFromLayers(manifest, releaseRef, targetVersion)
	}

	return parseReleaseReferences(refData, targetVersion, releaseRef)
}

func extractFromLayers(manifest *registryManifest, releaseRef, targetVersion string) error {
	return fmt.Errorf("release label not found; layer extraction not implemented — OCP images will use release-level scanning")
}

func parseReleaseReferences(refData, targetVersion, releaseRef string) (*ocpComponentMap, error) {
	var refs struct {
		Spec struct {
			Tags []struct {
				Name string `json:"name"`
				From struct {
					Name string `json:"name"`
				} `json:"from"`
			} `json:"tags"`
		} `json:"spec"`
	}
	if err := json.Unmarshal([]byte(refData), &refs); err != nil {
		return nil, fmt.Errorf("parsing release references: %w", err)
	}

	result := &ocpComponentMap{
		components: make(map[string]string),
		digestMap:  make(map[string]string),
	}

	for _, tag := range refs.Spec.Tags {
		imgRef := tag.From.Name
		if strings.Contains(imgRef, "ocp-v4.0-art-dev") {
			result.components[tag.Name] = imgRef
			if idx := strings.Index(imgRef, "@"); idx >= 0 {
				digest := imgRef[idx+1:]
				result.digestMap[digest] = imgRef
			}
		}
	}

	return result, nil
}

type registryManifest struct {
	Config struct {
		Digest string `json:"digest"`
	} `json:"config"`
	Layers []struct {
		Digest string `json:"digest"`
	} `json:"layers"`
}

func fetchRegistryManifest(registry, repo, tag string) (*registryManifest, error) {
	url := fmt.Sprintf("https://%s/v2/%s/manifests/%s", registry, repo, tag)
	client := &http.Client{
		Timeout:   30 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: false}},
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.docker.distribution.manifest.v2+json, application/vnd.oci.image.manifest.v1+json")

	token, err := fetchQuayToken(registry, repo)
	if err == nil && token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("registry returned %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))
	if err != nil {
		return nil, err
	}

	var m registryManifest
	if err := json.Unmarshal(body, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

func fetchRegistryBlob(registry, repo, digest string) ([]byte, error) {
	url := fmt.Sprintf("https://%s/v2/%s/blobs/%s", registry, repo, digest)
	client := &http.Client{
		Timeout:   30 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: false}},
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	token, err := fetchQuayToken(registry, repo)
	if err == nil && token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("blob fetch returned %d", resp.StatusCode)
	}

	return io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
}

func fetchQuayToken(registry, repo string) (string, error) {
	url := fmt.Sprintf("https://%s/v2/auth?service=%s&scope=repository:%s:pull", registry, registry, repo)
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
		Token string `json:"token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", err
	}
	return tokenResp.Token, nil
}

// ScanOCPComponents extracts the OCP release payload for the target version,
// then scans each component individually to provide per-component fix status.
func ScanOCPComponents(ctx context.Context, records []cveatypes.CVERecord, settings *cveatypes.Settings, logf func(string, ...interface{}), progressFn func(done, total int)) {
	if settings.OCPTargetVersion == "" {
		logf("  SKIP: OCP target version not configured")
		return
	}

	ocpRecords := make(map[int]bool)
	currentDigests := make(map[string]bool)
	for i, r := range records {
		if strings.HasPrefix(r.ImageFull, ocpArtDevPrefix) {
			ocpRecords[i] = true
			if idx := strings.Index(r.ImageFull, "@"); idx >= 0 {
				currentDigests[r.ImageFull[idx+1:]] = true
			}
		}
	}

	if len(ocpRecords) == 0 {
		logf("  No OCP core images in report")
		return
	}

	logf("  %d OCP core image records found, extracting %s release payload...", len(ocpRecords), settings.OCPTargetVersion)

	payload, err := extractOCPPayload(settings.OCPTargetVersion)
	if err != nil {
		logf("  WARNING: Could not extract OCP payload: %v", err)
		logf("  Falling back to release-level scanning for OCP images")
		return
	}

	logf("  Extracted %d component references from release payload", len(payload.components))

	targetDigests := make(map[string]bool)
	for _, ref := range payload.components {
		if idx := strings.Index(ref, "@"); idx >= 0 {
			targetDigests[ref[idx+1:]] = true
		}
	}

	same := 0
	changed := 0
	for d := range currentDigests {
		if targetDigests[d] {
			same++
		} else {
			changed++
		}
	}
	logf("  OCP digests: %d unchanged, %d changed in %s", same, changed, settings.OCPTargetVersion)

	uniqueTargetRefs := make(map[string]bool)
	for _, ref := range payload.components {
		uniqueTargetRefs[ref] = true
	}

	logf("  Scanning %d unique target component images...", len(uniqueTargetRefs))

	type componentScan struct {
		ref      string
		cveSet   map[string]bool
		scanErr  string
	}

	scanCache := make(map[string]*componentScan)
	var mu sync.Mutex
	var wg sync.WaitGroup

	workers := settings.ScanWorkers
	if workers <= 0 {
		workers = 4
	}
	sem := make(chan struct{}, workers)

	done := 0
	total := len(uniqueTargetRefs)

	for ref := range uniqueTargetRefs {
		wg.Add(1)
		sem <- struct{}{}
		go func(imageRef string) {
			defer wg.Done()
			defer func() { <-sem }()

			cs := &componentScan{ref: imageRef, cveSet: make(map[string]bool)}

			adminCtx := sac.WithAllAccess(ctx)
			enrichCtx := imageEnricher.EnrichmentContext{
				FetchOpt: imageEnricher.UseImageNamesRefetchCachedValues,
				Internal: true,
			}

			scan, err := enrichImage(adminCtx, enrichCtx, imageRef)
			if err != nil {
				cs.scanErr = err.Error()
			} else if scan != nil {
				for _, comp := range scan.GetComponents() {
					for _, vuln := range comp.GetVulns() {
						if cveID := vuln.GetCve(); cveID != "" {
							cs.cveSet[cveID] = true
						}
					}
				}
			}

			mu.Lock()
			scanCache[imageRef] = cs
			done++
			if progressFn != nil {
				progressFn(done, total)
			}
			mu.Unlock()
		}(ref)
	}
	wg.Wait()

	scanErrors := 0
	for _, cs := range scanCache {
		if cs.scanErr != "" {
			scanErrors++
		}
	}
	logf("  Component scans: %d OK, %d errors", len(scanCache)-scanErrors, scanErrors)

	allTargetCVEs := make(map[string]bool)
	for _, cs := range scanCache {
		for cve := range cs.cveSet {
			allTargetCVEs[cve] = true
		}
	}

	releaseRef := fmt.Sprintf("quay.io/openshift-release-dev/ocp-release:%s-x86_64", settings.OCPTargetVersion)
	catalogURL := fmt.Sprintf("https://quay.io/repository/openshift-release-dev/ocp-release?tag=%s-x86_64", settings.OCPTargetVersion)

	fixed := 0
	vulnerable := 0

	for i := range records {
		if !ocpRecords[i] {
			continue
		}
		r := &records[i]
		currentDigest := ""
		if idx := strings.Index(r.ImageFull, "@"); idx >= 0 {
			currentDigest = r.ImageFull[idx+1:]
		}

		if targetDigests[currentDigest] {
			r.FixStatus = fixStatusVulnerable
			r.FixLatestRef = r.ImageFull
			r.FixLatestTag = settings.OCPTargetVersion + " (same digest)"
			vulnerable++
			continue
		}

		targetRef := ""
		for _, ref := range payload.digestMap {
			if ref != "" {
				targetRef = ref
				break
			}
		}
		if targetRef == "" {
			targetRef = releaseRef
		}

		componentTargetRef := ""
		for compName, ref := range payload.components {
			if cs, ok := scanCache[ref]; ok {
				if strings.Contains(r.ImageFull, compName) || (currentDigest != "" && payload.digestMap[currentDigest] != "") {
					componentTargetRef = ref
					if _, hasCVE := cs.cveSet[r.CVE]; hasCVE {
						r.FixStatus = fixStatusVulnerable
						r.FixLatestRef = ref
						r.FixLatestTag = settings.OCPTargetVersion
						r.FixCatalogURL = catalogURL
						vulnerable++
					} else {
						r.FixStatus = fixStatusFixed
						r.FixLatestRef = ref
						r.FixLatestTag = settings.OCPTargetVersion
						r.FixCatalogURL = catalogURL
						fixed++
					}
					break
				}
			}
		}

		if componentTargetRef == "" {
			if allTargetCVEs[r.CVE] {
				r.FixStatus = fixStatusVulnerable
				r.FixLatestRef = releaseRef
				r.FixLatestTag = settings.OCPTargetVersion
				r.FixCatalogURL = catalogURL
				vulnerable++
			} else {
				r.FixStatus = fixStatusFixed
				r.FixLatestRef = releaseRef
				r.FixLatestTag = settings.OCPTargetVersion
				r.FixCatalogURL = catalogURL
				fixed++
			}
		}
	}

	logf("  OCP component results: %d fixed, %d still vulnerable", fixed, vulnerable)
}
