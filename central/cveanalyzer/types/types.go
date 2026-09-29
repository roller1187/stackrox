package types

import "time"

type ReportStatus string

const (
	StatusPending  ReportStatus = "pending"
	StatusQueued   ReportStatus = "queued"
	StatusRunning  ReportStatus = "running"
	StatusComplete ReportStatus = "complete"
	StatusError    ReportStatus = "error"
)

type Report struct {
	ID            string       `json:"id"`
	Name          string       `json:"name"`
	Filename      string       `json:"filename,omitempty"`
	Status        ReportStatus `json:"status"`
	Step          string       `json:"step,omitempty"`
	RecordCount   *int         `json:"record_count"`
	CreatedAt     time.Time    `json:"created_at"`
	CompletedAt   *time.Time   `json:"completed_at,omitempty"`
	RegeneratedAt *time.Time   `json:"regenerated_at,omitempty"`
	Error         string       `json:"error,omitempty"`
	Warnings      []string     `json:"warnings,omitempty"`
}

type CVERecord struct {
	ID               int64  `json:"-"`
	ReportID         string `json:"-"`
	Key              string `json:"key"`
	CVE              string `json:"cve"`
	Priority         string `json:"priority"`
	Action           string `json:"action"`
	Severity         string `json:"severity"`
	CVSS             string `json:"cvss"`
	NvdCVSS          string `json:"nvd_cvss"`
	EpssPct          string `json:"epss_pct"`
	Product          string `json:"product"`
	ImageShort       string `json:"image_short"`
	ImageFull        string `json:"image_full"`
	Cluster          string `json:"cluster"`
	Namespaces       string `json:"namespaces"`
	Deployments      string `json:"deployments"`
	Component        string `json:"component"`
	ComponentVersion string `json:"component_version"`
	FixedIn          string `json:"fixed_in"`
	RHSAAdvisory     string `json:"rhsa_advisory"`
	AdvisoryLink     string `json:"advisory_link"`
	PrimaryLink      string `json:"primary_link"`
	SecondaryLink    string `json:"secondary_link"`
	TertiaryLink     string `json:"tertiary_link"`
	RemediationPath  string `json:"remediation_path"`
	TriageReasoning  string `json:"triage_reasoning"`
	OSVVerification  string `json:"osv_verification"`
	OSVAffectedRange string `json:"osv_affected_range"`
	POAMJustification string `json:"poam_justification"`
	Discovered       string `json:"discovered"`
	RoxStatus        string `json:"rox_status"`
	RoxFixVersion    string `json:"rox_fix_version"`
	RHCVSS           string `json:"rh_cvss"`
	RHSeverity       string `json:"rh_severity"`
	RHVector         string `json:"rh_vector"`
	RHMitigation     string `json:"rh_mitigation"`
	RHStatement      string `json:"rh_statement"`
	FixStatus        string `json:"fix_status"`
	FixLatestRef     string `json:"fix_latest_ref"`
	FixLatestTag     string `json:"fix_latest_tag"`
	FixCatalogURL    string `json:"fix_catalog_url"`
	FixScanError     string `json:"fix_scan_error"`
	FixPublishedDate string `json:"fix_published_date"`
	RHSADescription  string `json:"rhsa_description"`
	KEVDateAdded     string `json:"kev_date_added"`
	KEVDueDate       string `json:"kev_due_date"`
	SLADeadline      string `json:"sla_deadline"`
	SLATier          string `json:"sla_tier"`
	CVEPublished     string `json:"cve_published"`
	ImageCatalogURL  string `json:"image_catalog_url"`
}

type Settings struct {
	RoxEndpoint            string `json:"rox_endpoint"`
	RoxAPIToken            string `json:"rox_api_token"`
	PullSecret             string `json:"pull_secret"`
	OCPTargetVersion       string `json:"ocp_target_version"`
	OCPCurrentVersion      string `json:"ocp_current_version"`
	SkipTLSVerify          bool   `json:"skip_tls_verify"`
	ScanWorkers            int    `json:"scan_workers"`
	AutoRegenerateEnabled  bool   `json:"auto_regenerate_enabled"`
	AutoRegenerateSchedule string `json:"auto_regenerate_schedule"`
	AutoRegenerateTimezone string `json:"auto_regenerate_timezone"`
	MaxConcurrentPipelines int    `json:"max_concurrent_pipelines"`
}

type UpdateEntry struct {
	Fields       map[string]FieldChange `json:"fields"`
	DetectedAt   string                 `json:"detected_at"`
	Acknowledged bool                   `json:"acknowledged"`
}

type FieldChange struct {
	Old string `json:"old"`
	New string `json:"new"`
}

type PreflightResult struct {
	Warnings []string `json:"warnings"`
}
