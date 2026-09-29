package export

import (
	"fmt"
	"html"
	"io"

	cveatypes "github.com/stackrox/rox/central/cveanalyzer/types"
)

var priorityColors = map[string]string{
	"P1-CRITICAL":    "#dc2626",
	"P1-HIGH-EPSS":   "#dc2626",
	"P2-HIGH-IMPACT": "#ea580c",
	"P2-HIGH-EPSS":   "#ea580c",
	"P3-MODERATE":    "#d97706",
	"P4-MONITOR":     "#2563eb",
	"P5-LOW":         "#6b7280",
}

var actionColors = map[string]string{
	"PATCH":   "#dc2626",
	"MONITOR": "#2563eb",
}

// GenerateHTML writes a standalone HTML report to the writer.
func GenerateHTML(w io.Writer, report *cveatypes.Report, records []cveatypes.CVERecord) {
	title := "CVE Analysis Report"
	if report != nil {
		title = html.EscapeString(report.Name) + " - CVE Analysis Report"
	}

	fmt.Fprintf(w, `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>%s</title>
<style>
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 20px; background: #0f172a; color: #e2e8f0; }
h1 { color: #f1f5f9; }
table { border-collapse: collapse; width: 100%%; font-size: 13px; }
th, td { border: 1px solid #334155; padding: 6px 10px; text-align: left; }
th { background: #1e293b; color: #94a3b8; font-weight: 600; text-transform: uppercase; font-size: 11px; }
tr:nth-child(even) { background: rgba(255,255,255,.02); }
tr:hover { background: rgba(255,255,255,.05); }
.badge { display: inline-block; padding: 2px 8px; border-radius: 4px; color: #fff; font-size: 11px; font-weight: 600; }
a { color: #38bdf8; text-decoration: none; }
a:hover { text-decoration: underline; }
.summary { display: flex; gap: 16px; margin: 16px 0; flex-wrap: wrap; }
.stat { background: #1e293b; border-radius: 8px; padding: 12px 20px; text-align: center; min-width: 100px; }
.stat-value { font-size: 24px; font-weight: 700; }
.stat-label { font-size: 11px; color: #94a3b8; margin-top: 4px; }
.kev-row { border-left: 3px solid #d97706 !important; }
</style>
</head>
<body>
<h1>%s</h1>
`, title, title)

	// Summary stats
	patchCount := 0
	monitorCount := 0
	kevCount := 0
	uniqueCVEs := make(map[string]bool)
	fixedCount := 0
	for _, r := range records {
		uniqueCVEs[r.CVE] = true
		if r.Action == "PATCH" {
			patchCount++
		} else {
			monitorCount++
		}
		if r.KEVDateAdded != "" {
			kevCount++
		}
		if r.FixStatus == "FIXED_IN_LATEST" {
			fixedCount++
		}
	}

	fmt.Fprintf(w, `<div class="summary">
<div class="stat"><div class="stat-value">%d</div><div class="stat-label">Total Records</div></div>
<div class="stat"><div class="stat-value">%d</div><div class="stat-label">Unique CVEs</div></div>
<div class="stat"><div class="stat-value" style="color:#dc2626">%d</div><div class="stat-label">PATCH</div></div>
<div class="stat"><div class="stat-value" style="color:#2563eb">%d</div><div class="stat-label">MONITOR</div></div>
<div class="stat"><div class="stat-value" style="color:#d97706">%d</div><div class="stat-label">KEV</div></div>
<div class="stat"><div class="stat-value" style="color:#16a34a">%d</div><div class="stat-label">Fixed</div></div>
</div>
`, len(records), len(uniqueCVEs), patchCount, monitorCount, kevCount, fixedCount)

	// Table
	fmt.Fprint(w, `<table>
<thead><tr>
<th>Priority</th><th>Action</th><th>CVE</th><th>Severity</th>
<th>CVSS</th><th>RH CVSS</th><th>EPSS</th>
<th>Product</th><th>Image</th><th>Component</th>
<th>Fixed In</th><th>Fix Status</th><th>RHSA</th>
<th>Discovered</th><th>SLA</th>
</tr></thead>
<tbody>
`)

	for _, r := range records {
		rowClass := ""
		if r.KEVDateAdded != "" {
			rowClass = ` class="kev-row"`
		}

		priColor := priorityColors[r.Priority]
		if priColor == "" {
			priColor = "#6b7280"
		}
		actColor := actionColors[r.Action]
		if actColor == "" {
			actColor = "#6b7280"
		}

		cveLink := html.EscapeString(r.CVE)
		if r.PrimaryLink != "" {
			cveLink = fmt.Sprintf(`<a href="%s" target="_blank">%s</a>`,
				html.EscapeString(r.PrimaryLink), html.EscapeString(r.CVE))
		}

		fixStatusDisplay := r.FixStatus
		switch r.FixStatus {
		case "FIXED_IN_LATEST":
			fixStatusDisplay = `<span style="color:#16a34a">FIXED</span>`
		case "STILL_VULNERABLE":
			fixStatusDisplay = `<span style="color:#dc2626">NOT FIXED</span>`
		}

		rhsa := html.EscapeString(r.RHSAAdvisory)
		if r.AdvisoryLink != "" && r.RHSAAdvisory != "" {
			rhsa = fmt.Sprintf(`<a href="%s" target="_blank">%s</a>`,
				html.EscapeString(r.AdvisoryLink), html.EscapeString(r.RHSAAdvisory))
		}

		fmt.Fprintf(w, `<tr%s>
<td><span class="badge" style="background:%s">%s</span></td>
<td><span class="badge" style="background:%s">%s</span></td>
<td>%s</td>
<td>%s</td>
<td>%s</td><td>%s</td><td>%s</td>
<td>%s</td><td>%s</td><td>%s</td>
<td>%s</td><td>%s</td><td>%s</td>
<td>%s</td><td>%s</td>
</tr>
`,
			rowClass,
			priColor, html.EscapeString(r.Priority),
			actColor, html.EscapeString(r.Action),
			cveLink,
			html.EscapeString(r.Severity),
			html.EscapeString(r.CVSS),
			html.EscapeString(r.RHCVSS),
			formatEPSS(r.EpssPct),
			html.EscapeString(r.Product),
			html.EscapeString(r.ImageShort),
			html.EscapeString(r.Component),
			html.EscapeString(r.FixedIn),
			fixStatusDisplay,
			rhsa,
			html.EscapeString(r.Discovered),
			html.EscapeString(r.SLADeadline),
		)
	}

	fmt.Fprint(w, `</tbody></table>
<p style="margin-top:20px;font-size:11px;color:#64748b">
Generated by RHACS CVE Analyzer
</p>
</body></html>`)
}

func formatEPSS(s string) string {
	if s == "" || s == "0" {
		return ""
	}
	return html.EscapeString(s) + "%"
}
