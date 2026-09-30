package pipeline

import (
	"testing"

	cveatypes "github.com/stackrox/rox/central/cveanalyzer/types"
	"github.com/stretchr/testify/assert"
)

func TestCarryForwardEnrichment(t *testing.T) {
	t.Run("carries forward when new record is empty", func(t *testing.T) {
		old := []cveatypes.CVERecord{{
			Key:        "CVE-2024-1234|||registry.redhat.io/rhel9/go-toolset@sha256:abc",
			RHCVSS:     "7.1",
			RHSeverity: "Important",
			RHVector:   "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
			RoxStatus:  "CONFIRMED",
			FixStatus:  "FIXED_IN_LATEST",
		}}
		new := []cveatypes.CVERecord{{
			Key: "CVE-2024-1234|||registry.redhat.io/rhel9/go-toolset@sha256:abc",
		}}

		carried := carryForwardEnrichment(old, new)

		assert.Equal(t, 1, carried)
		assert.Equal(t, "7.1", new[0].RHCVSS)
		assert.Equal(t, "Important", new[0].RHSeverity)
		assert.Equal(t, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", new[0].RHVector)
		assert.Equal(t, "CONFIRMED", new[0].RoxStatus)
		assert.Equal(t, "FIXED_IN_LATEST", new[0].FixStatus)
	})

	t.Run("does not overwrite when new record has data", func(t *testing.T) {
		old := []cveatypes.CVERecord{{
			Key:        "CVE-2024-1234|||img",
			RHCVSS:     "7.1",
			RHSeverity: "Important",
		}}
		new := []cveatypes.CVERecord{{
			Key:        "CVE-2024-1234|||img",
			RHCVSS:     "8.5",
			RHSeverity: "Critical",
		}}

		carried := carryForwardEnrichment(old, new)

		assert.Equal(t, 0, carried)
		assert.Equal(t, "8.5", new[0].RHCVSS)
		assert.Equal(t, "Critical", new[0].RHSeverity)
	})

	t.Run("handles new CVEs not in old data", func(t *testing.T) {
		old := []cveatypes.CVERecord{{
			Key:    "CVE-2024-1111|||img",
			RHCVSS: "5.0",
		}}
		new := []cveatypes.CVERecord{{
			Key: "CVE-2024-9999|||img",
		}}

		carried := carryForwardEnrichment(old, new)

		assert.Equal(t, 0, carried)
		assert.Equal(t, "", new[0].RHCVSS)
	})

	t.Run("carries KEV data together", func(t *testing.T) {
		old := []cveatypes.CVERecord{{
			Key:          "CVE-2024-1234|||img",
			KEVDateAdded: "2024-06-01",
			KEVDueDate:   "2024-06-15",
		}}
		new := []cveatypes.CVERecord{{
			Key: "CVE-2024-1234|||img",
		}}

		carryForwardEnrichment(old, new)

		assert.Equal(t, "2024-06-01", new[0].KEVDateAdded)
		assert.Equal(t, "2024-06-15", new[0].KEVDueDate)
	})

	t.Run("carries fix status fields together", func(t *testing.T) {
		old := []cveatypes.CVERecord{{
			Key:            "CVE-2024-1234|||img",
			FixStatus:      "STILL_VULNERABLE",
			FixLatestTag:   "4.18.54",
			FixLatestRef:   "quay.io/repo@sha256:abc",
			FixCatalogURL:  "https://quay.io/repository/repo/manifest/sha256:abc",
			FixPublishedDate: "2024-09-01",
		}}
		new := []cveatypes.CVERecord{{
			Key: "CVE-2024-1234|||img",
		}}

		carryForwardEnrichment(old, new)

		assert.Equal(t, "STILL_VULNERABLE", new[0].FixStatus)
		assert.Equal(t, "4.18.54", new[0].FixLatestTag)
		assert.Equal(t, "quay.io/repo@sha256:abc", new[0].FixLatestRef)
		assert.Equal(t, "https://quay.io/repository/repo/manifest/sha256:abc", new[0].FixCatalogURL)
		assert.Equal(t, "2024-09-01", new[0].FixPublishedDate)
	})
}
