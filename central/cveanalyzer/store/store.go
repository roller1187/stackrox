package store

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	cveatypes "github.com/stackrox/rox/central/cveanalyzer/types"
	"github.com/stackrox/rox/pkg/logging"
	"github.com/stackrox/rox/pkg/postgres"
	"github.com/stackrox/rox/pkg/uuid"
)

var log = logging.LoggerForModule()

const schema = `
CREATE TABLE IF NOT EXISTS cve_analyzer_reports (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    filename TEXT DEFAULT '',
    status TEXT NOT NULL DEFAULT 'pending',
    step TEXT DEFAULT '',
    record_count INT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    regenerated_at TIMESTAMPTZ,
    error TEXT DEFAULT '',
    warnings JSONB DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS cve_analyzer_records (
    id BIGSERIAL PRIMARY KEY,
    report_id TEXT NOT NULL REFERENCES cve_analyzer_reports(id) ON DELETE CASCADE,
    key TEXT NOT NULL,
    data JSONB NOT NULL,
    UNIQUE(report_id, key)
);

CREATE TABLE IF NOT EXISTS cve_analyzer_settings (
    id INT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    data JSONB NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS cve_analyzer_processed_keys (
    report_id TEXT NOT NULL REFERENCES cve_analyzer_reports(id) ON DELETE CASCADE,
    key TEXT NOT NULL,
    PRIMARY KEY(report_id, key)
);

CREATE TABLE IF NOT EXISTS cve_analyzer_fp_keys (
    report_id TEXT NOT NULL REFERENCES cve_analyzer_reports(id) ON DELETE CASCADE,
    key TEXT NOT NULL,
    PRIMARY KEY(report_id, key)
);

CREATE TABLE IF NOT EXISTS cve_analyzer_updates (
    report_id TEXT NOT NULL REFERENCES cve_analyzer_reports(id) ON DELETE CASCADE,
    key TEXT NOT NULL,
    fields JSONB NOT NULL DEFAULT '{}',
    detected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    acknowledged BOOLEAN DEFAULT FALSE,
    PRIMARY KEY(report_id, key)
);

CREATE TABLE IF NOT EXISTS cve_analyzer_raw_csv (
    report_id TEXT NOT NULL REFERENCES cve_analyzer_reports(id) ON DELETE CASCADE,
    csv_data BYTEA NOT NULL,
    PRIMARY KEY(report_id)
);

CREATE TABLE IF NOT EXISTS cve_analyzer_notes (
    report_id TEXT NOT NULL REFERENCES cve_analyzer_reports(id) ON DELETE CASCADE,
    data JSONB NOT NULL DEFAULT '{}',
    PRIMARY KEY(report_id)
);
`

// Store provides persistence for the CVE Analyzer.
type Store struct {
	db postgres.DB
}

// New creates a new Store and ensures the schema exists.
func New(db postgres.DB) *Store {
	s := &Store{db: db}
	ctx := context.Background()
	if _, err := db.Exec(ctx, schema); err != nil {
		log.Errorf("Failed to create CVE Analyzer schema: %v", err)
	}
	return s
}

// --- Reports ---

func (s *Store) CreateReport(ctx context.Context, name, filename string) (*cveatypes.Report, error) {
	id := uuid.NewV4().String()
	now := time.Now()
	_, err := s.db.Exec(ctx,
		`INSERT INTO cve_analyzer_reports (id, name, filename, status, created_at) VALUES ($1, $2, $3, $4, $5)`,
		id, name, filename, cveatypes.StatusPending, now)
	if err != nil {
		return nil, fmt.Errorf("creating report: %w", err)
	}
	return &cveatypes.Report{
		ID:        id,
		Name:      name,
		Filename:  filename,
		Status:    cveatypes.StatusPending,
		CreatedAt: now,
	}, nil
}

func (s *Store) ListReports(ctx context.Context) ([]cveatypes.Report, error) {
	rows, err := s.db.Query(ctx,
		`SELECT id, name, filename, status, step, record_count, created_at, completed_at, regenerated_at, error, warnings
		 FROM cve_analyzer_reports ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("listing reports: %w", err)
	}
	defer rows.Close()
	var reports []cveatypes.Report
	for rows.Next() {
		r, err := scanReport(rows)
		if err != nil {
			return nil, err
		}
		reports = append(reports, r)
	}
	if reports == nil {
		reports = []cveatypes.Report{}
	}
	return reports, rows.Err()
}

func (s *Store) GetReport(ctx context.Context, id string) (*cveatypes.Report, error) {
	rows, err := s.db.Query(ctx,
		`SELECT id, name, filename, status, step, record_count, created_at, completed_at, regenerated_at, error, warnings
		 FROM cve_analyzer_reports WHERE id = $1`, id)
	if err != nil {
		return nil, fmt.Errorf("getting report: %w", err)
	}
	defer rows.Close()
	if !rows.Next() {
		return nil, nil
	}
	r, err := scanReport(rows)
	if err != nil {
		return nil, err
	}
	return &r, nil
}

func scanReport(rows *postgres.Rows) (cveatypes.Report, error) {
	var r cveatypes.Report
	var recordCount *int
	var completedAt, regeneratedAt *time.Time
	var warningsJSON []byte
	err := rows.Scan(&r.ID, &r.Name, &r.Filename, &r.Status, &r.Step,
		&recordCount, &r.CreatedAt, &completedAt, &regeneratedAt, &r.Error, &warningsJSON)
	if err != nil {
		return r, fmt.Errorf("scanning report: %w", err)
	}
	r.RecordCount = recordCount
	r.CompletedAt = completedAt
	r.RegeneratedAt = regeneratedAt
	if len(warningsJSON) > 0 {
		_ = json.Unmarshal(warningsJSON, &r.Warnings)
	}
	if r.Warnings == nil {
		r.Warnings = []string{}
	}
	return r, nil
}

func (s *Store) UpdateReportStatus(ctx context.Context, id string, status cveatypes.ReportStatus, step string, errMsg string) error {
	_, err := s.db.Exec(ctx,
		`UPDATE cve_analyzer_reports SET status = $2, step = $3, error = $4 WHERE id = $1`,
		id, status, step, errMsg)
	return err
}

func (s *Store) CompleteReport(ctx context.Context, id string, recordCount int, isRegen bool) error {
	now := time.Now()
	if isRegen {
		_, err := s.db.Exec(ctx,
			`UPDATE cve_analyzer_reports SET status = $2, step = '', record_count = $3, completed_at = $4, regenerated_at = $4, error = '' WHERE id = $1`,
			id, cveatypes.StatusComplete, recordCount, now)
		return err
	}
	_, err := s.db.Exec(ctx,
		`UPDATE cve_analyzer_reports SET status = $2, step = '', record_count = $3, completed_at = $4, error = '' WHERE id = $1`,
		id, cveatypes.StatusComplete, recordCount, now)
	return err
}

func (s *Store) DeleteReport(ctx context.Context, id string) error {
	_, err := s.db.Exec(ctx, `DELETE FROM cve_analyzer_reports WHERE id = $1`, id)
	return err
}

func (s *Store) SetReportWarnings(ctx context.Context, id string, warnings []string) error {
	data, _ := json.Marshal(warnings)
	_, err := s.db.Exec(ctx, `UPDATE cve_analyzer_reports SET warnings = $2 WHERE id = $1`, id, data)
	return err
}

// --- Raw CSV ---

func (s *Store) StoreRawCSV(ctx context.Context, reportID string, csvData []byte) error {
	_, err := s.db.Exec(ctx,
		`INSERT INTO cve_analyzer_raw_csv (report_id, csv_data) VALUES ($1, $2)
		 ON CONFLICT (report_id) DO UPDATE SET csv_data = EXCLUDED.csv_data`,
		reportID, csvData)
	return err
}

func (s *Store) GetRawCSV(ctx context.Context, reportID string) ([]byte, error) {
	row := s.db.QueryRow(ctx, `SELECT csv_data FROM cve_analyzer_raw_csv WHERE report_id = $1`, reportID)
	var data []byte
	err := row.Scan(&data)
	if err != nil {
		return nil, err
	}
	return data, nil
}

// --- Records ---

func (s *Store) ReplaceRecords(ctx context.Context, reportID string, records []cveatypes.CVERecord) error {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback(ctx)

	_, err = tx.Exec(ctx, `DELETE FROM cve_analyzer_records WHERE report_id = $1`, reportID)
	if err != nil {
		return fmt.Errorf("deleting old records: %w", err)
	}

	for _, rec := range records {
		data, err := json.Marshal(rec)
		if err != nil {
			return fmt.Errorf("marshaling record: %w", err)
		}
		_, err = tx.Exec(ctx,
			`INSERT INTO cve_analyzer_records (report_id, key, data) VALUES ($1, $2, $3)`,
			reportID, rec.Key, data)
		if err != nil {
			return fmt.Errorf("inserting record %s: %w", rec.Key, err)
		}
	}

	return tx.Commit(ctx)
}

func (s *Store) GetRecords(ctx context.Context, reportID string) ([]cveatypes.CVERecord, error) {
	rows, err := s.db.Query(ctx,
		`SELECT data FROM cve_analyzer_records WHERE report_id = $1 ORDER BY id`, reportID)
	if err != nil {
		return nil, fmt.Errorf("querying records: %w", err)
	}
	defer rows.Close()

	var records []cveatypes.CVERecord
	for rows.Next() {
		var data []byte
		if err := rows.Scan(&data); err != nil {
			return nil, fmt.Errorf("scanning record: %w", err)
		}
		var rec cveatypes.CVERecord
		if err := json.Unmarshal(data, &rec); err != nil {
			return nil, fmt.Errorf("unmarshaling record: %w", err)
		}
		records = append(records, rec)
	}
	if records == nil {
		records = []cveatypes.CVERecord{}
	}
	return records, rows.Err()
}

// --- Processed / FP Keys ---

func (s *Store) GetProcessedKeys(ctx context.Context, reportID string) ([]string, error) {
	return s.getKeys(ctx, "cve_analyzer_processed_keys", reportID)
}

func (s *Store) SaveProcessedKeys(ctx context.Context, reportID string, keys []string) error {
	return s.saveKeys(ctx, "cve_analyzer_processed_keys", reportID, keys)
}

func (s *Store) GetFPKeys(ctx context.Context, reportID string) ([]string, error) {
	return s.getKeys(ctx, "cve_analyzer_fp_keys", reportID)
}

func (s *Store) SaveFPKeys(ctx context.Context, reportID string, keys []string) error {
	return s.saveKeys(ctx, "cve_analyzer_fp_keys", reportID, keys)
}

func (s *Store) getKeys(ctx context.Context, table, reportID string) ([]string, error) {
	rows, err := s.db.Query(ctx,
		fmt.Sprintf(`SELECT key FROM %s WHERE report_id = $1`, table), reportID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var keys []string
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err != nil {
			return nil, err
		}
		keys = append(keys, k)
	}
	if keys == nil {
		keys = []string{}
	}
	return keys, rows.Err()
}

func (s *Store) saveKeys(ctx context.Context, table, reportID string, keys []string) error {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	_, err = tx.Exec(ctx, fmt.Sprintf(`DELETE FROM %s WHERE report_id = $1`, table), reportID)
	if err != nil {
		return err
	}

	if len(keys) > 0 {
		var sb strings.Builder
		sb.WriteString(fmt.Sprintf(`INSERT INTO %s (report_id, key) VALUES `, table))
		args := make([]interface{}, 0, len(keys)+1)
		args = append(args, reportID)
		for i, k := range keys {
			if i > 0 {
				sb.WriteString(", ")
			}
			sb.WriteString(fmt.Sprintf("($1, $%d)", i+2))
			args = append(args, k)
		}
		sb.WriteString(" ON CONFLICT DO NOTHING")
		_, err = tx.Exec(ctx, sb.String(), args...)
		if err != nil {
			return err
		}
	}

	return tx.Commit(ctx)
}

// --- Updates ---

func (s *Store) GetUpdates(ctx context.Context, reportID string) (map[string]cveatypes.UpdateEntry, error) {
	rows, err := s.db.Query(ctx,
		`SELECT key, fields, detected_at, acknowledged FROM cve_analyzer_updates WHERE report_id = $1`, reportID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := make(map[string]cveatypes.UpdateEntry)
	for rows.Next() {
		var key string
		var fieldsJSON []byte
		var detectedAt time.Time
		var acked bool
		if err := rows.Scan(&key, &fieldsJSON, &detectedAt, &acked); err != nil {
			return nil, err
		}
		var fields map[string]cveatypes.FieldChange
		_ = json.Unmarshal(fieldsJSON, &fields)
		result[key] = cveatypes.UpdateEntry{
			Fields:       fields,
			DetectedAt:   detectedAt.Format(time.RFC3339),
			Acknowledged: acked,
		}
	}
	return result, rows.Err()
}

func (s *Store) AcknowledgeUpdates(ctx context.Context, reportID string, keys []string) error {
	if len(keys) == 0 {
		return nil
	}
	placeholders := make([]string, len(keys))
	args := make([]interface{}, len(keys)+1)
	args[0] = reportID
	for i, k := range keys {
		placeholders[i] = fmt.Sprintf("$%d", i+2)
		args[i+1] = k
	}
	_, err := s.db.Exec(ctx,
		fmt.Sprintf(`UPDATE cve_analyzer_updates SET acknowledged = TRUE WHERE report_id = $1 AND key IN (%s)`,
			strings.Join(placeholders, ", ")),
		args...)
	return err
}

func (s *Store) SaveUpdates(ctx context.Context, reportID string, updates map[string]cveatypes.UpdateEntry) error {
	for key, entry := range updates {
		fieldsJSON, _ := json.Marshal(entry.Fields)
		_, err := s.db.Exec(ctx,
			`INSERT INTO cve_analyzer_updates (report_id, key, fields, acknowledged)
			 VALUES ($1, $2, $3, $4)
			 ON CONFLICT (report_id, key) DO UPDATE SET fields = EXCLUDED.fields, detected_at = NOW(), acknowledged = EXCLUDED.acknowledged`,
			reportID, key, fieldsJSON, entry.Acknowledged)
		if err != nil {
			return err
		}
	}
	return nil
}

// --- Settings ---

func (s *Store) GetSettings(ctx context.Context) (*cveatypes.Settings, error) {
	row := s.db.QueryRow(ctx, `SELECT data FROM cve_analyzer_settings WHERE id = 1`)
	var data []byte
	err := row.Scan(&data)
	if err != nil {
		if err == pgx.ErrNoRows {
			return defaultSettings(), nil
		}
		return nil, err
	}
	var settings cveatypes.Settings
	if err := json.Unmarshal(data, &settings); err != nil {
		return defaultSettings(), nil
	}
	return &settings, nil
}

func (s *Store) SaveSettings(ctx context.Context, settings *cveatypes.Settings) error {
	data, err := json.Marshal(settings)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(ctx,
		`INSERT INTO cve_analyzer_settings (id, data) VALUES (1, $1)
		 ON CONFLICT (id) DO UPDATE SET data = EXCLUDED.data`, data)
	return err
}

// --- Notes ---

func (s *Store) GetNotes(ctx context.Context, reportID string) (map[string]string, error) {
	row := s.db.QueryRow(ctx, `SELECT data FROM cve_analyzer_notes WHERE report_id = $1`, reportID)
	var data []byte
	err := row.Scan(&data)
	if err != nil {
		if err == pgx.ErrNoRows {
			return map[string]string{}, nil
		}
		return nil, err
	}
	var notes map[string]string
	if err := json.Unmarshal(data, &notes); err != nil {
		return map[string]string{}, nil
	}
	return notes, nil
}

func (s *Store) SaveNotes(ctx context.Context, reportID string, notes map[string]string) error {
	data, err := json.Marshal(notes)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(ctx,
		`INSERT INTO cve_analyzer_notes (report_id, data) VALUES ($1, $2)
		 ON CONFLICT (report_id) DO UPDATE SET data = EXCLUDED.data`,
		reportID, data)
	return err
}

func defaultSettings() *cveatypes.Settings {
	return &cveatypes.Settings{
		ScanWorkers:            4,
		AutoRegenerateSchedule: "0 6 * * *",
		AutoRegenerateTimezone: "UTC",
		MaxConcurrentPipelines: 2,
	}
}
