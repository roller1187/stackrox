package pipeline

import (
	"encoding/csv"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"

	cveatypes "github.com/stackrox/rox/central/cveanalyzer/types"
)

// Product line mapping: image namespace -> product name
var nsProduct = map[string]string{
	"advanced-cluster-security":  "RHACS (StackRox)",
	"cert-manager":               "Cert-Manager",
	"compliance":                 "Compliance Operator",
	"devspaces":                  "Dev Spaces",
	"devworkspace":               "Dev Spaces",
	"external-secrets-operator":  "External Secrets Operator",
	"jetstack":                   "Cert-Manager CSI Sidecars",
	"kube-descheduler-operator":  "Kube Descheduler",
	"multicluster-engine":        "Multicluster Engine (MCE)",
	"openshift":                  "OpenShift CLI",
	"openshift-gitops-1":         "OpenShift GitOps",
	"openshift-logging":          "OpenShift Logging",
	"openshift-release-dev":      "OpenShift Core (OCP)",
	"prometheus":                 "Blackbox Exporter (3rd-party)",
	"redhat":                     "Operator Index",
	"rhacm2":                     "RHACM (ACM)",
	"rhbk":                       "Red Hat Build of Keycloak",
	"rhel8":                      "RHEL8 Base Image",
	"rhel9":                      "RHEL9 Base Image",
	"rhosdt":                     "OpenTelemetry",
	"web-terminal":               "Web Terminal",
}

var imgProduct = map[string]string{
	"ose-aws-efs-csi-driver-container-rhel9": "AWS EFS CSI Driver",
	"ose-aws-efs-csi-driver-rhel9-operator":  "AWS EFS CSI Driver",
	"ose-csi-external-provisioner-rhel9":     "CSI Sidecars (OCP)",
	"ose-csi-livenessprobe-rhel9":            "CSI Sidecars (OCP)",
	"ose-csi-node-driver-registrar-rhel9":    "CSI Sidecars (OCP)",
	"ose-kube-rbac-proxy":                    "Kube RBAC Proxy (OCP)",
	"ose-kube-rbac-proxy-rhel9":              "Kube RBAC Proxy (OCP)",
	"ose-oauth-proxy":                        "OAuth Proxy (OCP)",
}

var nsRemediation = map[string]string{
	"advanced-cluster-security":  "Update RHACS operator via OLM",
	"cert-manager":               "Update cert-manager operator via OLM",
	"compliance":                 "Update compliance-operator via OLM",
	"devspaces":                  "Update devspaces operator via OLM",
	"devworkspace":               "Update devspaces operator via OLM",
	"external-secrets-operator":  "Update external-secrets-operator via OLM",
	"jetstack":                   "Update cert-manager operator via OLM",
	"kube-descheduler-operator":  "Update kube-descheduler-operator via OLM",
	"multicluster-engine":        "Update multicluster-engine operator via OLM",
	"openshift":                  "Upgrade OCP cluster or update oc client image",
	"openshift-gitops-1":         "Update openshift-gitops-operator via OLM",
	"openshift-logging":          "Update cluster-logging operator via OLM",
	"openshift-release-dev":      "Upgrade OCP cluster to next available z-stream",
	"redhat":                     "Update redhat-operator catalogsource",
	"rhacm2":                     "Update advanced-cluster-management operator via OLM",
	"rhbk":                       "Update rhbk-operator via OLM",
	"rhosdt":                     "Update opentelemetry-product operator via OLM",
	"web-terminal":               "Update web-terminal operator via OLM",
}

var allowedRegistries = []string{
	"registry.redhat.io/",
	"quay.io/",
}

var priorityOrder = map[string]int{
	"P1-CRITICAL":    0,
	"P1-HIGH-EPSS":   1,
	"P2-HIGH-IMPACT": 2,
	"P2-HIGH-EPSS":   3,
	"P3-MODERATE":    4,
	"P4-MONITOR":     5,
	"P5-LOW":         6,
}

func parseImage(imageRef string) (registry, ns, short string) {
	ref := imageRef
	if idx := strings.Index(ref, "@"); idx >= 0 {
		ref = ref[:idx]
	} else if idx := strings.LastIndex(ref, ":"); idx >= 0 {
		ref = ref[:idx]
	}
	parts := strings.Split(ref, "/")
	switch {
	case len(parts) >= 3:
		registry = parts[0]
		ns = parts[1]
		short = parts[len(parts)-1]
	case len(parts) == 2:
		registry = parts[0]
		short = parts[1]
	default:
		short = parts[0]
	}
	return
}

func getProductLine(imageRef string) string {
	_, ns, short := parseImage(imageRef)
	if p, ok := imgProduct[short]; ok {
		return p
	}
	if strings.Contains(ns, "redhat-services-prod") {
		return "SRE Managed Services"
	}
	if p, ok := nsProduct[ns]; ok {
		return p
	}
	if ns != "" {
		return strings.Title(strings.ReplaceAll(ns, "-", " "))
	}
	return "Unknown"
}

func getRemediation(imageRef string) string {
	_, ns, _ := parseImage(imageRef)
	if strings.Contains(ns, "redhat-services-prod") {
		return "Contact SRE team / managed by Red Hat SRE"
	}
	if r, ok := nsRemediation[ns]; ok {
		return r
	}
	if ns != "" {
		return fmt.Sprintf("Update %s operator via OLM", ns)
	}
	return "Update image"
}

func computePriority(severity string, cvss, epss float64) (priority, action string) {
	if severity == "CRITICAL" || (cvss >= 9.0 && epss >= 1.0) {
		return "P1-CRITICAL", "PATCH"
	}
	if epss >= 10.0 {
		return "P1-HIGH-EPSS", "PATCH"
	}
	if cvss >= 9.0 || (cvss >= 8.0 && epss >= 1.0) {
		return "P2-HIGH-IMPACT", "PATCH"
	}
	if epss >= 5.0 {
		return "P2-HIGH-EPSS", "PATCH"
	}
	if cvss >= 8.0 || (cvss >= 7.0 && epss >= 1.0) {
		return "P3-MODERATE", "PATCH"
	}
	if cvss >= 7.0 || (severity == "IMPORTANT" && cvss >= 6.0) {
		return "P4-MONITOR", "MONITOR"
	}
	return "P5-LOW", "MONITOR"
}

func triageReasoning(severity string, cvss, epss float64, nvdCVSS string) string {
	var parts []string
	if severity != "" {
		parts = append(parts, severity+" severity")
	}
	if cvss > 0 {
		parts = append(parts, fmt.Sprintf("CVSS %.1f", cvss))
	}
	if nvdCVSS != "" && nvdCVSS != "0" && nvdCVSS != fmt.Sprintf("%.1f", cvss) {
		parts = append(parts, "NVD CVSS "+nvdCVSS)
	}
	if epss > 0 {
		parts = append(parts, fmt.Sprintf("EPSS %.1f%%", epss))
	}
	if len(parts) == 0 {
		return "No CVSS scored yet, low EPSS (0.0%) - monitor for NVD scoring"
	}
	return strings.Join(parts, ", ")
}

func poamJustification(priority, action, fixedIn, remediation string) string {
	if action == "UPDATE" {
		urgency := "MODERATE"
		if strings.HasPrefix(priority, "P1") {
			urgency = "URGENT"
		} else if strings.HasPrefix(priority, "P2") {
			urgency = "HIGH"
		}
		return fmt.Sprintf("POA&M Required (%s). Fixed in latest image — update deployment. %s", urgency, remediation)
	}
	if action == "PATCH" {
		urgency := "MODERATE"
		if strings.HasPrefix(priority, "P1") {
			urgency = "URGENT"
		} else if strings.HasPrefix(priority, "P2") {
			urgency = "HIGH"
		}
		fixNote := "No fix available yet - monitor upstream."
		if fixedIn != "" {
			fixNote = fmt.Sprintf("Fix available in %s.", fixedIn)
		}
		return fmt.Sprintf("POA&M Required (%s). Constraint: %s - %s", urgency, remediation, fixNote)
	}
	return fmt.Sprintf("POA&M Informational. Low-risk, monitor for upstream patches. %s", remediation)
}

// RefineActions adjusts the action field based on enrichment data collected during the pipeline.
// Must run after all enrichment steps (Red Hat scores, image scanning, OCP components).
func RefineActions(records []cveatypes.CVERecord, logf func(string, ...interface{})) {
	var updated, toUpdate, toMonitor int
	for i := range records {
		r := &records[i]
		origAction := r.Action

		// RH says not affected or won't fix → MONITOR regardless of score
		switch r.RHFixState {
		case "Will not fix", "Not affected", "Fix deferred":
			r.Action = "MONITOR"
			if origAction != "MONITOR" {
				toMonitor++
			}
			r.POAMJustification = poamJustification(r.Priority, r.Action, r.FixedIn, r.RemediationPath)
			continue
		}

		// Only refine records that scored high enough for PATCH
		if origAction != "PATCH" {
			continue
		}

		if r.FixStatus == "FIXED_IN_LATEST" {
			r.Action = "UPDATE"
			toUpdate++
		} else if r.FixedIn == "" && r.FixStatus != "FIXED_IN_LATEST" {
			// No component fix and latest image doesn't resolve it
			r.Action = "MONITOR"
			toMonitor++
		}

		if r.Action != origAction {
			r.POAMJustification = poamJustification(r.Priority, r.Action, r.FixedIn, r.RemediationPath)
			updated++
		}
	}
	logf("  Refined actions: %d UPDATE, %d downgraded to MONITOR, %d total changed", toUpdate, toMonitor, updated)
}

type csvGroup struct {
	namespaces  map[string]bool
	deployments map[string]bool
	components  map[string]bool
	versions    map[string]bool
	clusters    map[string]bool
	firstRow    map[string]string
}

// ParseAndTriage parses a raw RHACS CSV export and produces enriched CVERecord entries.
func ParseAndTriage(csvData []byte) ([]cveatypes.CVERecord, error) {
	reader := csv.NewReader(strings.NewReader(string(csvData)))
	reader.LazyQuotes = true
	reader.FieldsPerRecord = -1

	headers, err := reader.Read()
	if err != nil {
		return nil, fmt.Errorf("reading CSV headers: %w", err)
	}

	colIdx := make(map[string]int)
	for i, h := range headers {
		colIdx[h] = i
	}

	getField := func(row []string, field string) string {
		if idx, ok := colIdx[field]; ok && idx < len(row) {
			return strings.TrimSpace(row[idx])
		}
		return ""
	}

	groups := make(map[string]*csvGroup)
	var groupOrder []string

	for {
		row, err := reader.Read()
		if err != nil {
			break
		}

		cve := getField(row, "CVE")
		if cve == "" {
			continue
		}
		image := getField(row, "Image")
		if image == "" {
			continue
		}

		// Filter non-Red Hat registries
		allowed := false
		for _, prefix := range allowedRegistries {
			if strings.HasPrefix(image, prefix) {
				allowed = true
				break
			}
		}
		if !allowed {
			continue
		}

		key := cve + "|||" + image
		g, exists := groups[key]
		if !exists {
			g = &csvGroup{
				namespaces:  make(map[string]bool),
				deployments: make(map[string]bool),
				components:  make(map[string]bool),
				versions:    make(map[string]bool),
				clusters:    make(map[string]bool),
			}
			groups[key] = g
			groupOrder = append(groupOrder, key)
		}
		if g.firstRow == nil {
			rowMap := make(map[string]string)
			for _, h := range headers {
				rowMap[h] = getField(row, h)
			}
			g.firstRow = rowMap
		}
		g.namespaces[getField(row, "Namespace")] = true
		g.deployments[getField(row, "Deployment")] = true
		g.components[getField(row, "Component")] = true
		g.versions[getField(row, "Component Version")] = true
		g.clusters[getField(row, "Cluster")] = true
	}

	if len(groups) == 0 {
		return nil, fmt.Errorf("no valid CVE records found in CSV")
	}

	var records []cveatypes.CVERecord
	for _, key := range groupOrder {
		g := groups[key]
		r := g.firstRow

		severity := r["Severity"]
		cvss := parseFloat(r["CVSS"])
		nvdCVSS := r["NVDCVSS"]
		if nvdCVSS == "" {
			nvdCVSS = r["NVD CVSS"]
		}
		epss := parseFloat(r["EPSS Probability Percentage"])
		fixedIn := r["CVE Fixed In"]
		image := r["Image"]
		_, _, short := parseImage(image)
		product := getProductLine(image)
		remediation := getRemediation(image)
		priority, action := computePriority(severity, cvss, epss)

		rec := cveatypes.CVERecord{
			Key:              key,
			CVE:              r["CVE"],
			Priority:         priority,
			Action:           action,
			Severity:         severity,
			CVSS:             formatFloat(cvss),
			NvdCVSS:          nvdCVSS,
			EpssPct:          formatFloat(epss),
			Product:          product,
			ImageShort:       short,
			ImageFull:        image,
			ImageCatalogURL:  buildCurrentImageCatalogURL(image),
			Cluster:          joinSorted(g.clusters),
			Namespaces:       joinSorted(g.namespaces),
			Deployments:      joinSorted(g.deployments),
			Component:        joinSorted(g.components),
			ComponentVersion: joinSorted(g.versions),
			FixedIn:          fixedIn,
			RHSAAdvisory:     r["Advisory Name"],
			AdvisoryLink:     r["Advisory Link"],
			PrimaryLink:      r["Reference"],
			RemediationPath:  remediation,
			TriageReasoning:  triageReasoning(severity, cvss, epss, nvdCVSS),
			POAMJustification: poamJustification(priority, action, fixedIn, remediation),
			Discovered:       r["Discovered At"],
		}
		records = append(records, rec)
	}

	// Sort by priority then CVSS descending
	sort.Slice(records, func(i, j int) bool {
		pi := priorityOrder[records[i].Priority]
		pj := priorityOrder[records[j].Priority]
		if pi != pj {
			return pi < pj
		}
		ci := parseFloat(records[i].CVSS)
		cj := parseFloat(records[j].CVSS)
		return ci > cj
	})

	return records, nil
}

func parseFloat(s string) float64 {
	f, _ := strconv.ParseFloat(strings.TrimSpace(s), 64)
	return f
}

func formatFloat(f float64) string {
	if f == 0 {
		return "0"
	}
	if f == math.Trunc(f) {
		return fmt.Sprintf("%.1f", f)
	}
	return strconv.FormatFloat(f, 'f', -1, 64)
}

func joinSorted(m map[string]bool) string {
	var items []string
	for k := range m {
		if k != "" {
			items = append(items, k)
		}
	}
	sort.Strings(items)
	return strings.Join(items, "; ")
}

func buildCurrentImageCatalogURL(imageRef string) string {
	base := imageRef
	if idx := strings.Index(base, "@"); idx >= 0 {
		base = base[:idx]
	} else if idx := strings.LastIndex(base, ":"); idx >= 0 {
		base = base[:idx]
	}

	if strings.HasPrefix(base, "registry.redhat.io/") {
		repoPath := strings.TrimPrefix(base, "registry.redhat.io/")
		return "https://catalog.redhat.com/en/software/containers/" + repoPath
	}
	if strings.HasPrefix(base, "quay.io/") {
		repoPath := strings.TrimPrefix(base, "quay.io/")
		if strings.Contains(imageRef, "@sha256:") {
			digest := imageRef[strings.Index(imageRef, "@")+1:]
			return "https://quay.io/repository/" + repoPath + "/manifest/" + digest
		}
		return "https://quay.io/repository/" + repoPath
	}
	return ""
}
