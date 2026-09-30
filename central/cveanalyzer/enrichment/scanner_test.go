package enrichment

import (
	"testing"

	cveatypes "github.com/stackrox/rox/central/cveanalyzer/types"
	"github.com/stretchr/testify/assert"
)

func TestBuildCatalogURL(t *testing.T) {
	tests := map[string]struct {
		base   string
		digest string
		want   string
	}{
		"ocp-v4.0-art-dev links to manifest": {
			base:   "quay.io/openshift-release-dev/ocp-v4.0-art-dev",
			digest: "sha256:abc123",
			want:   "https://quay.io/repository/openshift-release-dev/ocp-v4.0-art-dev/manifest/sha256:abc123",
		},
		"quay.io with digest links to manifest": {
			base:   "quay.io/rhacm2/registration-operator",
			digest: "sha256:abc123def456",
			want:   "https://quay.io/repository/rhacm2/registration-operator/manifest/sha256:abc123def456",
		},
		"quay.io without digest links to repo": {
			base:   "quay.io/rhacm2/registration-operator",
			digest: "",
			want:   "https://quay.io/repository/rhacm2/registration-operator",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got := buildCatalogURL(tc.base, tc.digest)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestExtractBase(t *testing.T) {
	tests := map[string]struct {
		imageRef string
		want     string
	}{
		"digest ref": {
			imageRef: "quay.io/openshift-release-dev/ocp-v4.0-art-dev@sha256:abc123",
			want:     "quay.io/openshift-release-dev/ocp-v4.0-art-dev",
		},
		"tagged ref": {
			imageRef: "registry.redhat.io/rhel9/go-toolset:1.21",
			want:     "registry.redhat.io/rhel9/go-toolset",
		},
		"bare ref": {
			imageRef: "registry.redhat.io/ubi9/ubi-minimal",
			want:     "registry.redhat.io/ubi9/ubi-minimal",
		},
		"digest with long hash": {
			imageRef: "quay.io/rhacm2/multicloud-manager@sha256:bffc170ad32a20191102119f0423376ff9e3eb1d459ea455ed8cc6e5bbd05a43",
			want:     "quay.io/rhacm2/multicloud-manager",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got := extractBase(tc.imageRef)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestIsVersionTag(t *testing.T) {
	tests := map[string]struct {
		tag  string
		want bool
	}{
		"semver":            {tag: "1.21.3", want: true},
		"v-prefix semver":   {tag: "v4.18.54", want: true},
		"two-part":          {tag: "2.11", want: true},
		"numeric only short": {tag: "123", want: true},
		"latest":            {tag: "latest", want: false},
		"empty":             {tag: "", want: false},
		"signature":         {tag: "sha256-abc.sig", want: false},
		"attestation":       {tag: "sha256-abc.att", want: false},
		"source":            {tag: "1.21-source", want: false},
		"long numeric epoch": {tag: "1234567890", want: false},
		"date tag":          {tag: "2026.09.29", want: true},
		"release with arch": {tag: "v4.18.54-x86_64", want: true},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got := isVersionTag(tc.tag)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestCompareVersionTags(t *testing.T) {
	tests := map[string]struct {
		a      string
		b      string
		wantGt bool
		wantEq bool
	}{
		"higher patch":         {a: "1.21.4", b: "1.21.3", wantGt: true},
		"higher minor":         {a: "1.22.0", b: "1.21.9", wantGt: true},
		"higher major":         {a: "2.0.0", b: "1.99.99", wantGt: true},
		"v prefix ignored":     {a: "v4.18.54", b: "4.18.53", wantGt: true},
		"equal":                {a: "1.21.3", b: "1.21.3", wantEq: true},
		"lower returns false":  {a: "1.20.0", b: "1.21.0"},
		"hyphenated segments":  {a: "4.18.54-x86_64", b: "4.17.99-x86_64", wantGt: true},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			cmp := compareVersionTags(tc.a, tc.b)
			if tc.wantGt {
				assert.Greater(t, cmp, 0, "%s should be greater than %s", tc.a, tc.b)
			} else if tc.wantEq {
				assert.Equal(t, 0, cmp)
			} else {
				assert.Less(t, cmp, 0, "%s should be less than %s", tc.a, tc.b)
			}
		})
	}
}

func TestBestVersionTag(t *testing.T) {
	tests := map[string]struct {
		tags []string
		want string
	}{
		"picks highest version": {
			tags: []string{"1.21.3", "1.22.0", "1.20.1"},
			want: "1.22.0",
		},
		"ignores latest": {
			tags: []string{"latest", "1.21.3", "1.22.0"},
			want: "1.22.0",
		},
		"ignores signatures": {
			tags: []string{"sha256-abc.sig", "1.21.3"},
			want: "1.21.3",
		},
		"handles v prefix": {
			tags: []string{"v4.17.0", "v4.18.54"},
			want: "v4.18.54",
		},
		"no usable tags": {
			tags: []string{"latest", "sha256-abc.sig"},
			want: "",
		},
		"empty": {
			tags: nil,
			want: "",
		},
		"mixed formats": {
			tags: []string{"1.2.3", "v2.0.0", "3.0.0-rc1", "latest"},
			want: "3.0.0-rc1",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got := bestVersionTag(tc.tags)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestResolveLatestRef_OCPArtDev(t *testing.T) {
	tests := map[string]struct {
		base    string
		ocpVer  string
		wantRef string
		wantErr bool
	}{
		"ocp-v4.0-art-dev with target version": {
			base:    "quay.io/openshift-release-dev/ocp-v4.0-art-dev",
			ocpVer:  "4.18.54",
			wantRef: "quay.io/openshift-release-dev/ocp-release:4.18.54-x86_64",
		},
		"ocp-v4.0-art-dev without target version errors": {
			base:    "quay.io/openshift-release-dev/ocp-v4.0-art-dev",
			ocpVer:  "",
			wantErr: true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			settings := &cveatypes.Settings{OCPTargetVersion: tc.ocpVer}
			ref, _, _, err := resolveLatestRef(tc.base, settings)
			if tc.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.wantRef, ref)
			}
		})
	}
}
