package pipeline

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBuildCurrentImageCatalogURL(t *testing.T) {
	tests := map[string]struct {
		imageRef string
		want     string
	}{
		"registry.redhat.io with digest": {
			imageRef: "registry.redhat.io/rhel9/go-toolset@sha256:abc123def456",
			want:     "https://catalog.redhat.com/en/software/containers/rhel9/go-toolset",
		},
		"registry.redhat.io with tag": {
			imageRef: "registry.redhat.io/rhel9/go-toolset:1.21",
			want:     "https://catalog.redhat.com/en/software/containers/rhel9/go-toolset",
		},
		"registry.redhat.io bare": {
			imageRef: "registry.redhat.io/ubi9/ubi-minimal",
			want:     "https://catalog.redhat.com/en/software/containers/ubi9/ubi-minimal",
		},
		"quay.io with digest": {
			imageRef: "quay.io/rhacm2/registration-operator@sha256:abc123",
			want:     "https://quay.io/repository/rhacm2/registration-operator/manifest/sha256:abc123",
		},
		"quay.io with tag": {
			imageRef: "quay.io/rhacm2/registration-operator:2.11",
			want:     "https://quay.io/repository/rhacm2/registration-operator",
		},
		"ocp-v4.0-art-dev with digest links to manifest": {
			imageRef: "quay.io/openshift-release-dev/ocp-v4.0-art-dev@sha256:bffc170ad32a20191102119f0423376ff9e3eb1d459ea455ed8cc6e5bbd05a43",
			want:     "https://quay.io/repository/openshift-release-dev/ocp-v4.0-art-dev/manifest/sha256:bffc170ad32a20191102119f0423376ff9e3eb1d459ea455ed8cc6e5bbd05a43",
		},
		"ocp-v4.0-art-dev with tag links to repo": {
			imageRef: "quay.io/openshift-release-dev/ocp-v4.0-art-dev:4.18-something",
			want:     "https://quay.io/repository/openshift-release-dev/ocp-v4.0-art-dev",
		},
		"unknown registry returns empty": {
			imageRef: "docker.io/library/nginx:latest",
			want:     "",
		},
		"empty string returns empty": {
			imageRef: "",
			want:     "",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got := buildCurrentImageCatalogURL(tc.imageRef)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestParseImage(t *testing.T) {
	tests := map[string]struct {
		imageRef             string
		wantRegistry         string
		wantNS               string
		wantShort            string
	}{
		"registry.redhat.io three-part with digest": {
			imageRef:     "registry.redhat.io/rhel9/go-toolset@sha256:abc123",
			wantRegistry: "registry.redhat.io",
			wantNS:       "rhel9",
			wantShort:    "go-toolset",
		},
		"quay.io ocp art-dev": {
			imageRef:     "quay.io/openshift-release-dev/ocp-v4.0-art-dev@sha256:abc",
			wantRegistry: "quay.io",
			wantNS:       "openshift-release-dev",
			wantShort:    "ocp-v4.0-art-dev",
		},
		"quay.io with tag": {
			imageRef:     "quay.io/rhacm2/multicloud-manager:2.11.0-DOWNSTREAM-2026-09-02",
			wantRegistry: "quay.io",
			wantNS:       "rhacm2",
			wantShort:    "multicloud-manager",
		},
		"two-part image": {
			imageRef:     "docker.io/nginx:latest",
			wantRegistry: "docker.io",
			wantNS:       "",
			wantShort:    "nginx",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			reg, ns, short := parseImage(tc.imageRef)
			assert.Equal(t, tc.wantRegistry, reg)
			assert.Equal(t, tc.wantNS, ns)
			assert.Equal(t, tc.wantShort, short)
		})
	}
}

func TestGetProductLine(t *testing.T) {
	tests := map[string]struct {
		imageRef string
		want     string
	}{
		"rhacs image": {
			imageRef: "registry.redhat.io/advanced-cluster-security/rhacs-main-rhel9:4.5",
			want:     "RHACS (StackRox)",
		},
		"ocp core": {
			imageRef: "quay.io/openshift-release-dev/ocp-v4.0-art-dev@sha256:abc",
			want:     "OpenShift Core (OCP)",
		},
		"acm image": {
			imageRef: "quay.io/rhacm2/registration-operator:2.11",
			want:     "RHACM (ACM)",
		},
		"image-specific override": {
			imageRef: "registry.redhat.io/openshift4/ose-kube-rbac-proxy-rhel9:v4.16",
			want:     "Kube RBAC Proxy (OCP)",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got := getProductLine(tc.imageRef)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestComputePriority(t *testing.T) {
	tests := map[string]struct {
		severity     string
		cvss         float64
		epss         float64
		wantPriority string
		wantAction   string
	}{
		"critical severity": {
			severity: "CRITICAL", cvss: 9.8, epss: 5.0,
			wantPriority: "P1-CRITICAL", wantAction: "PATCH",
		},
		"high EPSS": {
			severity: "HIGH", cvss: 7.0, epss: 12.0,
			wantPriority: "P1-HIGH-EPSS", wantAction: "PATCH",
		},
		"high impact": {
			severity: "HIGH", cvss: 9.2, epss: 0.5,
			wantPriority: "P2-HIGH-IMPACT", wantAction: "PATCH",
		},
		"moderate": {
			severity: "HIGH", cvss: 8.1, epss: 0.3,
			wantPriority: "P3-MODERATE", wantAction: "PATCH",
		},
		"monitor": {
			severity: "IMPORTANT", cvss: 7.5, epss: 0.1,
			wantPriority: "P4-MONITOR", wantAction: "MONITOR",
		},
		"low": {
			severity: "LOW", cvss: 3.0, epss: 0.01,
			wantPriority: "P5-LOW", wantAction: "MONITOR",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			p, a := computePriority(tc.severity, tc.cvss, tc.epss)
			assert.Equal(t, tc.wantPriority, p)
			assert.Equal(t, tc.wantAction, a)
		})
	}
}
