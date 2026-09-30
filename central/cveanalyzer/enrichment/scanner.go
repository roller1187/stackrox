package enrichment

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	centralEnrichment "github.com/stackrox/rox/central/enrichment"
	cveatypes "github.com/stackrox/rox/central/cveanalyzer/types"
	"github.com/stackrox/rox/generated/storage"
	imageEnricher "github.com/stackrox/rox/pkg/images/enricher"
	"github.com/stackrox/rox/pkg/sac"
)

const (
	fixStatusFixed       = "FIXED_IN_LATEST"
	fixStatusVulnerable  = "STILL_VULNERABLE"
	fixStatusUnavailable = "SCAN_UNAVAILABLE"

	pyxisAPI    = "https://catalog.redhat.com/api/containers/v1"
	catalogBase = "https://catalog.redhat.com/en/software/containers"
	quayAPI     = "https://quay.io/api/v1"
	httpTimeout = 30 * time.Second
)

var (
	versionTagRe   = regexp.MustCompile(`^v?\d+\.\d+`)
	numericOnlyRe  = regexp.MustCompile(`^\d+$`)
	versionStripRe = regexp.MustCompile(`^v`)
	versionSplitRe = regexp.MustCompile(`[.\-]`)

	ocpArtDevPrefix = "quay.io/openshift-release-dev/ocp-v4.0-art-dev"
)

type scanResult struct {
	imageKey   string
	fixStatus  string
	fixTag     string
	fixRef     string
	catalogURL string
	scanError  string
	cveResults map[string]bool
}

// enrichImage abstracts over the StackRox enricher singleton so callers
// never need to know which internal enricher variant is active.
// StackRox initializes exactly one enricher at startup based on the
// FlattenImageData feature flag — we check both and use whichever is live.
func enrichImage(ctx context.Context, enrichCtx imageEnricher.EnrichmentContext, name string) (*storage.ImageScan, error) {
	if enricher := centralEnrichment.ImageEnricherSingleton(); enricher != nil {
		img, err := imageEnricher.EnrichImageByName(ctx, enricher, enrichCtx, name)
		if err != nil {
			return nil, err
		}
		return img.GetScan(), nil
	}
	// FlattenImageData enabled — StackRox uses a different enricher implementation
	if enricher := centralEnrichment.ImageEnricherV2Singleton(); enricher != nil {
		img, err := imageEnricher.EnrichImageV2ByName(ctx, enricher, enrichCtx, name)
		if err != nil {
			return nil, err
		}
		return img.GetScan(), nil
	}
	return nil, fmt.Errorf("no image enricher available")
}

// ScanLatestImages scans the latest version of each image to check if CVEs are fixed.
func ScanLatestImages(ctx context.Context, records []cveatypes.CVERecord, settings *cveatypes.Settings, logf func(string, ...interface{}), progressFn func(done, total int)) {
	type imageGroup struct {
		imageRef string
		indices  []int
	}
	groups := make(map[string]*imageGroup)
	var groupOrder []string

	for i, r := range records {
		if r.ImageFull == "" {
			continue
		}
		key := r.ImageFull
		if g, ok := groups[key]; ok {
			g.indices = append(g.indices, i)
		} else {
			groups[key] = &imageGroup{imageRef: r.ImageFull, indices: []int{i}}
			groupOrder = append(groupOrder, key)
		}
	}

	logf("  Scanning latest versions of %d unique images", len(groups))

	workers := settings.ScanWorkers
	if workers <= 0 {
		workers = 4
	}

	results := make(map[string]*scanResult)
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, workers)
	totalImages := len(groupOrder)
	doneImages := 0

	for _, key := range groupOrder {
		g := groups[key]
		wg.Add(1)
		sem <- struct{}{}
		go func(img *imageGroup) {
			defer wg.Done()
			defer func() { <-sem }()
			defer func() {
				if r := recover(); r != nil {
					mu.Lock()
					results[img.imageRef] = &scanResult{
						imageKey:  img.imageRef,
						fixStatus: fixStatusUnavailable,
						scanError: fmt.Sprintf("Scan panic: %v", r),
					}
					doneImages++
					if progressFn != nil {
						progressFn(doneImages, totalImages)
					}
					mu.Unlock()
				}
			}()

			result := scanLatestImage(ctx, img.imageRef, settings)
			mu.Lock()
			results[img.imageRef] = result
			doneImages++
			if progressFn != nil {
				progressFn(doneImages, totalImages)
			}
			mu.Unlock()
		}(g)
	}
	wg.Wait()

	fixed := 0
	vulnerable := 0
	unavailable := 0

	for _, key := range groupOrder {
		g := groups[key]
		result, ok := results[key]
		if !ok {
			continue
		}

		for _, idx := range g.indices {
			r := &records[idx]
			r.FixStatus = result.fixStatus
			r.FixLatestTag = result.fixTag
			r.FixLatestRef = result.fixRef
			r.FixCatalogURL = result.catalogURL
			r.FixScanError = result.scanError

			if result.cveResults != nil {
				if _, found := result.cveResults[r.CVE]; found {
					r.FixStatus = fixStatusVulnerable
				} else {
					r.FixStatus = fixStatusFixed
				}
			}
		}

		switch result.fixStatus {
		case fixStatusFixed:
			fixed++
		case fixStatusVulnerable:
			vulnerable++
		default:
			unavailable++
		}
	}

	logf("  Scan results: %d fixed, %d vulnerable, %d unavailable (out of %d images)",
		fixed, vulnerable, unavailable, len(groups))
}

// ScanCurrentImages scans the current deployed images to verify which CVEs are present.
func ScanCurrentImages(ctx context.Context, records []cveatypes.CVERecord, logf func(string, ...interface{}), progressFn func(done, total int)) {
	groups := make(map[string]*currentImageGroup)
	var groupOrder []string

	for i, r := range records {
		if r.ImageFull == "" {
			continue
		}
		key := r.ImageFull
		if g, ok := groups[key]; ok {
			g.indices = append(g.indices, i)
		} else {
			groups[key] = &currentImageGroup{imageRef: r.ImageFull, indices: []int{i}}
			groupOrder = append(groupOrder, key)
		}
	}

	logf("  Verifying CVEs against %d unique current images", len(groups))

	scanResults := make(map[string]map[string]string)
	scanErrors := make(map[string]bool)
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 4)
	totalImages := len(groupOrder)
	doneImages := 0

	adminCtx := sac.WithAllAccess(ctx)
	enrichCtx := imageEnricher.EnrichmentContext{
		FetchOpt: imageEnricher.UseImageNamesRefetchCachedValues,
		Internal: true,
	}

	for _, key := range groupOrder {
		g := groups[key]
		wg.Add(1)
		sem <- struct{}{}
		go func(img *currentImageGroup) {
			defer wg.Done()
			defer func() { <-sem }()
			defer func() {
				if r := recover(); r != nil {
					mu.Lock()
					scanErrors[img.imageRef] = true
					doneImages++
					if progressFn != nil {
						progressFn(doneImages, totalImages)
					}
					mu.Unlock()
				}
			}()

			scan, err := enrichImage(adminCtx, enrichCtx, img.imageRef)

			mu.Lock()
			defer mu.Unlock()
			doneImages++
			if progressFn != nil {
				progressFn(doneImages, totalImages)
			}

			if err != nil || scan == nil {
				scanErrors[img.imageRef] = true
				return
			}

			cveMap := make(map[string]string)
			for _, comp := range scan.GetComponents() {
				for _, vuln := range comp.GetVulns() {
					cveID := vuln.GetCve()
					if cveID != "" {
						fixVer := vuln.GetFixedBy()
						cveMap[cveID] = fixVer
					}
				}
			}
			scanResults[img.imageRef] = cveMap
		}(g)
	}
	wg.Wait()

	confirmed := 0
	notFound := 0
	scanErr := 0

	for _, key := range groupOrder {
		g := groups[key]
		if scanErrors[key] {
			for _, idx := range g.indices {
				records[idx].RoxStatus = "SCAN_ERROR"
			}
			scanErr++
			continue
		}
		cveMap, ok := scanResults[key]
		if !ok {
			for _, idx := range g.indices {
				records[idx].RoxStatus = "SCAN_ERROR"
			}
			scanErr++
			continue
		}
		for _, idx := range g.indices {
			r := &records[idx]
			if fixVer, found := cveMap[r.CVE]; found {
				r.RoxStatus = "CONFIRMED"
				r.RoxFixVersion = fixVer
				confirmed++
			} else {
				r.RoxStatus = "NOT_FOUND"
				notFound++
			}
		}
	}

	logf("  Current image scan: %d confirmed, %d not found, %d errors (out of %d images)",
		confirmed, notFound, scanErr, len(groups))

	enrichCurrentImageCatalogURLs(records, groupOrder, groups, logf)
}

type currentImageGroup struct {
	imageRef string
	indices  []int
}

func enrichCurrentImageCatalogURLs(records []cveatypes.CVERecord, groupOrder []string, groups map[string]*currentImageGroup, logf func(string, ...interface{})) {
	type rhImage struct {
		imageRef string
		repoPath string
		digest   string
	}

	var rhImages []rhImage
	seen := make(map[string]bool)

	for _, key := range groupOrder {
		g := groups[key]
		ref := g.imageRef
		if seen[ref] || !strings.HasPrefix(ref, "registry.redhat.io/") {
			continue
		}
		seen[ref] = true

		base := extractBase(ref)
		repoPath := strings.TrimPrefix(base, "registry.redhat.io/")
		digest := ""
		if idx := strings.Index(ref, "@"); idx >= 0 {
			digest = ref[idx+1:]
		}
		rhImages = append(rhImages, rhImage{imageRef: ref, repoPath: repoPath, digest: digest})
	}

	if len(rhImages) == 0 {
		return
	}

	logf("  Resolving catalog URLs for %d registry.redhat.io images", len(rhImages))

	uniqueRepos := make(map[string]bool)
	uniqueDigests := make(map[string]bool)
	for _, img := range rhImages {
		uniqueRepos[img.repoPath] = true
		if img.digest != "" {
			uniqueDigests[img.digest] = true
		}
	}

	repoIDs := make(map[string]string)
	var repoMu sync.Mutex
	var repoWg sync.WaitGroup
	repoSem := make(chan struct{}, 8)
	for rp := range uniqueRepos {
		repoWg.Add(1)
		repoSem <- struct{}{}
		go func(repo string) {
			defer repoWg.Done()
			defer func() { <-repoSem }()
			id := fetchPyxisRepoID(repo)
			repoMu.Lock()
			repoIDs[repo] = id
			repoMu.Unlock()
		}(rp)
	}
	repoWg.Wait()

	imageIDs := make(map[string]string)
	var imgMu sync.Mutex
	var imgWg sync.WaitGroup
	imgSem := make(chan struct{}, 8)
	for d := range uniqueDigests {
		imgWg.Add(1)
		imgSem <- struct{}{}
		go func(digest string) {
			defer imgWg.Done()
			defer func() { <-imgSem }()
			id := fetchPyxisImageID(digest)
			imgMu.Lock()
			imageIDs[digest] = id
			imgMu.Unlock()
		}(d)
	}
	imgWg.Wait()

	catalogURLs := make(map[string]string)
	foundExact := 0
	foundRepo := 0
	for _, img := range rhImages {
		repoID := repoIDs[img.repoPath]
		imageID := imageIDs[img.digest]
		if repoID != "" && imageID != "" {
			catalogURLs[img.imageRef] = fmt.Sprintf("%s/%s/%s?image=%s", catalogBase, img.repoPath, repoID, imageID)
			foundExact++
		} else if repoID != "" {
			catalogURLs[img.imageRef] = fmt.Sprintf("%s/%s/%s", catalogBase, img.repoPath, repoID)
			foundRepo++
		}
	}

	for _, key := range groupOrder {
		g := groups[key]
		if url, ok := catalogURLs[g.imageRef]; ok {
			for _, idx := range g.indices {
				records[idx].ImageCatalogURL = url
			}
		}
	}

	logf("  Catalog URLs: %d exact image links, %d repo-level links (of %d RH images)",
		foundExact, foundRepo, len(rhImages))
}

func scanLatestImage(ctx context.Context, imageRef string, settings *cveatypes.Settings) *scanResult {
	result := &scanResult{
		imageKey:   imageRef,
		fixStatus:  fixStatusUnavailable,
		cveResults: make(map[string]bool),
	}

	base := extractBase(imageRef)

	latestRef, latestTag, latestDigest, err := resolveLatestRef(base, settings)
	if err != nil || latestRef == "" {
		errMsg := "Could not resolve latest image version"
		if err != nil {
			errMsg = fmt.Sprintf("Version resolution failed: %v", err)
		}
		result.scanError = errMsg
		return result
	}

	result.fixRef = latestRef
	result.fixTag = latestTag
	result.catalogURL = buildCatalogURL(base, latestDigest)

	adminCtx := sac.WithAllAccess(ctx)
	enrichCtx := imageEnricher.EnrichmentContext{
		FetchOpt: imageEnricher.UseImageNamesRefetchCachedValues,
		Internal: true,
	}

	scan, err := enrichImage(adminCtx, enrichCtx, latestRef)
	if err != nil {
		result.scanError = fmt.Sprintf("Scan failed: %v", err)
		return result
	}
	if scan == nil {
		result.scanError = "No scan results returned"
		return result
	}

	for _, comp := range scan.GetComponents() {
		for _, vuln := range comp.GetVulns() {
			if cveID := vuln.GetCve(); cveID != "" {
				result.cveResults[cveID] = true
			}
		}
	}

	if len(result.cveResults) == 0 {
		result.fixStatus = fixStatusFixed
	} else {
		result.fixStatus = fixStatusVulnerable
	}

	return result
}

// resolveLatestRef determines the latest image reference using registry APIs.
// Returns (fullRef, tag, digest, error).
func resolveLatestRef(base string, settings *cveatypes.Settings) (string, string, string, error) {
	// OCP core images: use target version if configured
	if strings.HasPrefix(base, ocpArtDevPrefix) {
		if settings.OCPTargetVersion != "" {
			ref := "quay.io/openshift-release-dev/ocp-release:" + settings.OCPTargetVersion + "-x86_64"
			return ref, settings.OCPTargetVersion, "", nil
		}
		return "", "", "", fmt.Errorf("OCP target version not configured — set it in System Configuration to enable OCP image scanning")
	}

	// registry.redhat.io: use Pyxis API
	if strings.HasPrefix(base, "registry.redhat.io/") {
		tag, digest, err := findLatestPyxis(base)
		if err == nil && tag != "" {
			if digest != "" {
				return base + "@" + digest, tag, digest, nil
			}
			return base + ":" + tag, tag, "", nil
		}
	}

	// quay.io: use Quay API
	if strings.HasPrefix(base, "quay.io/") {
		tag, digest, err := findLatestQuay(base)
		if err == nil && tag != "" {
			if digest != "" {
				return base + "@" + digest, tag, digest, nil
			}
			return base + ":" + tag, tag, "", nil
		}
	}

	// Fallback: use :latest tag
	return base + ":latest", "latest", "", nil
}

// buildCatalogURL builds a catalog link for the latest image.
func buildCatalogURL(base string, digest string) string {
	if strings.HasPrefix(base, "registry.redhat.io/") {
		repoPath := strings.TrimPrefix(base, "registry.redhat.io/")
		repoID := fetchPyxisRepoID(repoPath)
		if repoID != "" {
			if digest != "" {
				imageID := fetchPyxisImageID(digest)
				if imageID != "" {
					return fmt.Sprintf("%s/%s/%s?image=%s", catalogBase, repoPath, repoID, imageID)
				}
			}
			return fmt.Sprintf("%s/%s/%s", catalogBase, repoPath, repoID)
		}
	} else if strings.HasPrefix(base, "quay.io/") {
		repoPath := strings.TrimPrefix(base, "quay.io/")
		if digest != "" {
			return fmt.Sprintf("https://quay.io/repository/%s/manifest/%s", repoPath, digest)
		}
		return fmt.Sprintf("https://quay.io/repository/%s", repoPath)
	}
	return ""
}

func fetchPyxisRepoID(repoPath string) string {
	url := fmt.Sprintf("%s/repositories?filter=repository==%s", pyxisAPI, repoPath)
	body, err := httpGet(url)
	if err != nil {
		return ""
	}
	var resp struct {
		Data []struct {
			ID string `json:"_id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &resp); err != nil || len(resp.Data) == 0 {
		return ""
	}
	return resp.Data[0].ID
}

func fetchPyxisImageID(digest string) string {
	encoded := strings.ReplaceAll(digest, ":", "%3A")
	url := fmt.Sprintf("%s/images?filter=image_id%%3D%%3D%s", pyxisAPI, encoded)
	body, err := httpGet(url)
	if err != nil {
		return ""
	}
	var resp struct {
		Data []struct {
			ID string `json:"_id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &resp); err != nil || len(resp.Data) == 0 {
		return ""
	}
	return resp.Data[0].ID
}

// findLatestPyxis uses the Red Hat Pyxis API to find the latest version.
func findLatestPyxis(base string) (tag string, digest string, err error) {
	repoPath := strings.TrimPrefix(base, "registry.redhat.io/")
	url := fmt.Sprintf(
		"%s/repositories/registry/registry.access.redhat.com/repository/%s/images?sort_by=creation_date%%5Bdesc%%5D&page_size=50&filter=architecture==amd64",
		pyxisAPI, repoPath,
	)

	body, err := httpGet(url)
	if err != nil {
		return "", "", err
	}

	var resp struct {
		Data []struct {
			ImageID      string `json:"image_id"`
			CreationDate string `json:"creation_date"`
			Repositories []struct {
				Tags []struct {
					Name string `json:"name"`
				} `json:"tags"`
			} `json:"repositories"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return "", "", fmt.Errorf("pyxis parse error: %w", err)
	}
	if len(resp.Data) == 0 {
		return "", "", fmt.Errorf("no images found in pyxis for %s", repoPath)
	}

	var bestTag string
	var bestDigest string
	for _, img := range resp.Data {
		for _, repo := range img.Repositories {
			for _, t := range repo.Tags {
				if isVersionTag(t.Name) {
					if bestTag == "" || compareVersionTags(t.Name, bestTag) > 0 {
						bestTag = t.Name
						bestDigest = img.ImageID
					}
				}
			}
		}
	}

	if bestTag != "" {
		return bestTag, bestDigest, nil
	}

	for _, repo := range resp.Data[0].Repositories {
		for _, t := range repo.Tags {
			if t.Name != "" {
				return t.Name, resp.Data[0].ImageID, nil
			}
		}
	}

	return "", resp.Data[0].ImageID, nil
}

// findLatestQuay uses the Quay API to find the latest version.
func findLatestQuay(base string) (tag string, digest string, err error) {
	repoPath := strings.TrimPrefix(base, "quay.io/")
	url := fmt.Sprintf("%s/repository/%s/tag/?limit=50&onlyActiveTags=true", quayAPI, repoPath)

	body, err := httpGet(url)
	if err != nil {
		return "", "", err
	}

	var resp struct {
		Tags []struct {
			Name           string `json:"name"`
			ManifestDigest string `json:"manifest_digest"`
		} `json:"tags"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return "", "", fmt.Errorf("quay parse error: %w", err)
	}
	if len(resp.Tags) == 0 {
		return "", "", fmt.Errorf("no tags found in quay for %s", repoPath)
	}

	var bestTag string
	var bestDigest string
	for _, t := range resp.Tags {
		if isVersionTag(t.Name) {
			if bestTag == "" || compareVersionTags(t.Name, bestTag) > 0 {
				bestTag = t.Name
				bestDigest = t.ManifestDigest
			}
		}
	}

	if bestTag != "" {
		return bestTag, bestDigest, nil
	}

	return resp.Tags[0].Name, resp.Tags[0].ManifestDigest, nil
}

func isVersionTag(tag string) bool {
	if tag == "" || tag == "latest" {
		return false
	}
	if strings.HasSuffix(tag, ".sig") || strings.HasSuffix(tag, ".att") || strings.Contains(tag, "-source") {
		return false
	}
	if versionTagRe.MatchString(tag) {
		return true
	}
	if numericOnlyRe.MatchString(tag) && len(tag) <= 6 {
		return true
	}
	return false
}

func compareVersionTags(a, b string) int {
	keyA := versionKey(a)
	keyB := versionKey(b)
	minLen := len(keyA)
	if len(keyB) < minLen {
		minLen = len(keyB)
	}
	for i := 0; i < minLen; i++ {
		if keyA[i].isNum != keyB[i].isNum {
			if keyA[i].isNum {
				return -1
			}
			return 1
		}
		if keyA[i].isNum {
			if keyA[i].num != keyB[i].num {
				return keyA[i].num - keyB[i].num
			}
		} else {
			cmp := strings.Compare(keyA[i].str, keyB[i].str)
			if cmp != 0 {
				return cmp
			}
		}
	}
	return len(keyA) - len(keyB)
}

type versionPart struct {
	isNum bool
	num   int
	str   string
}

func versionKey(tag string) []versionPart {
	t := versionStripRe.ReplaceAllString(tag, "")
	parts := versionSplitRe.Split(t, -1)
	result := make([]versionPart, 0, len(parts))
	for _, p := range parts {
		if n, err := strconv.Atoi(p); err == nil {
			result = append(result, versionPart{isNum: true, num: n})
		} else {
			result = append(result, versionPart{str: p})
		}
	}
	return result
}

func bestVersionTag(tags []string) string {
	var candidates []string
	for _, t := range tags {
		if isVersionTag(t) {
			candidates = append(candidates, t)
		}
	}
	if len(candidates) == 0 {
		return ""
	}
	sort.Slice(candidates, func(i, j int) bool {
		return compareVersionTags(candidates[i], candidates[j]) < 0
	})
	return candidates[len(candidates)-1]
}

func extractBase(imageRef string) string {
	if idx := strings.Index(imageRef, "@sha256:"); idx >= 0 {
		return imageRef[:idx]
	}
	if idx := strings.LastIndex(imageRef, ":"); idx >= 0 {
		return imageRef[:idx]
	}
	return imageRef
}

func httpGet(url string) ([]byte, error) {
	client := &http.Client{Timeout: httpTimeout}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "RHACS-CVE-Analyzer/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d from %s", resp.StatusCode, url)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
	if err != nil {
		return nil, err
	}
	return body, nil
}
