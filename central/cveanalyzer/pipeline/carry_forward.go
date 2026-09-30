package pipeline

import cveatypes "github.com/stackrox/rox/central/cveanalyzer/types"

// carryForwardEnrichment pre-populates new records with enrichment-derived fields
// from old records. This ensures that if an external API fails during re-enrichment,
// the previously-known data survives rather than being lost.
// Each enrichment step will overwrite these values with fresh data when it succeeds.
func carryForwardEnrichment(oldRecords, newRecords []cveatypes.CVERecord) int {
	oldMap := make(map[string]*cveatypes.CVERecord, len(oldRecords))
	for i := range oldRecords {
		oldMap[oldRecords[i].Key] = &oldRecords[i]
	}

	carried := 0
	for i := range newRecords {
		r := &newRecords[i]
		old, ok := oldMap[r.Key]
		if !ok {
			continue
		}

		didCarry := false

		if r.RHCVSS == "" && old.RHCVSS != "" {
			r.RHCVSS = old.RHCVSS
			didCarry = true
		}
		if r.RHVector == "" && old.RHVector != "" {
			r.RHVector = old.RHVector
			didCarry = true
		}
		if r.RHSeverity == "" && old.RHSeverity != "" {
			r.RHSeverity = old.RHSeverity
			didCarry = true
		}
		if r.RHMitigation == "" && old.RHMitigation != "" {
			r.RHMitigation = old.RHMitigation
			didCarry = true
		}
		if r.RHStatement == "" && old.RHStatement != "" {
			r.RHStatement = old.RHStatement
			didCarry = true
		}
		if r.CVEPublished == "" && old.CVEPublished != "" {
			r.CVEPublished = old.CVEPublished
			didCarry = true
		}
		if r.RHFixState == "" && old.RHFixState != "" {
			r.RHFixState = old.RHFixState
			r.RHFixStateDetail = old.RHFixStateDetail
			didCarry = true
		}
		if r.KEVDateAdded == "" && old.KEVDateAdded != "" {
			r.KEVDateAdded = old.KEVDateAdded
			r.KEVDueDate = old.KEVDueDate
			didCarry = true
		}
		if r.RHSADescription == "" && old.RHSADescription != "" {
			r.RHSADescription = old.RHSADescription
			didCarry = true
		}
		if r.RoxStatus == "" && old.RoxStatus != "" {
			r.RoxStatus = old.RoxStatus
			r.RoxFixVersion = old.RoxFixVersion
			didCarry = true
		}
		if r.FixStatus == "" && old.FixStatus != "" {
			r.FixStatus = old.FixStatus
			r.FixLatestTag = old.FixLatestTag
			r.FixLatestRef = old.FixLatestRef
			r.FixCatalogURL = old.FixCatalogURL
			r.FixScanError = old.FixScanError
			r.FixPublishedDate = old.FixPublishedDate
			didCarry = true
		}
		if r.ImageCatalogURL == "" && old.ImageCatalogURL != "" {
			r.ImageCatalogURL = old.ImageCatalogURL
			didCarry = true
		}
		if r.SecondaryLink == "" && old.SecondaryLink != "" {
			r.SecondaryLink = old.SecondaryLink
			didCarry = true
		}
		if r.TertiaryLink == "" && old.TertiaryLink != "" {
			r.TertiaryLink = old.TertiaryLink
			didCarry = true
		}

		if didCarry {
			carried++
		}
	}

	return carried
}
