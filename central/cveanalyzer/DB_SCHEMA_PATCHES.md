# CVE Analyzer: Database Schema Patches

## Background

The custom Central build uses a **DB version trick**: the migration sequence number
is changed from 227 to 225 before compilation, then reverted after. This allows the
custom binary to run against the existing database without triggering migration
validation errors. However, it means migrations 226 and 227 never run, leaving
several database columns missing.

### Migration 225 -> 226 (`m_225_to_m_226_drop_unused_child_idx_indexes`)

Drops unused btree indexes on child table `idx` columns. **No schema impact** —
only removes redundant indexes. Safe to skip.

### Migration 226 -> 227 (`m_226_to_m_227_backfill_report_type`)

Adds the `type` column to `report_snapshots` table and backfills existing rows
with `type = 0`. This column is required by the V2 view-based report system,
which powers both:
- The "Export report as CSV" button in the Vulnerability Management Results page
- The "Analyze Latest Scan" feature in the CVE Analyzer

### GORM AutoMigrate (runs during migration process)

GORM AutoMigrate normally syncs the Go struct definitions with the database
schema on startup. Since migrations are skipped, AutoMigrate also doesn't run
for updated models. This leaves two columns missing from `image_cves_v2`:
- `cvebaseinfo_cisakev` (CISA Known Exploited Vulnerabilities flag)
- `cvebaseinfo_knownransomwarecampaign` (Known Ransomware Campaign flag)

These columns are referenced by the V2 report CSV generation query and by the
image reprocessor's INSERT/UPDATE statements.

## Symptoms When Columns Are Missing

1. **"Export report as CSV" fails silently** — the V2 view-based report API
   returns HTTP 500: `column report_snapshots.type does not exist`

2. **CVE Analyzer "Analyze Latest Scan" fails** — same root cause, report
   shows "Error" status

3. **Reprocessor errors in Central logs** — continuous warnings:
   `column "cvebaseinfo_cisakev" does not exist` for every image upsert

## Fix: SQL Patches

Run these statements against the Central database to add the missing columns.
All use `IF NOT EXISTS` / `IF EXISTS` to be safe for re-running.

```sql
-- Patch 1: Add 'type' column to report_snapshots (migration 226->227)
ALTER TABLE report_snapshots ADD COLUMN IF NOT EXISTS type integer DEFAULT 0;
UPDATE report_snapshots SET type = 0 WHERE type IS NULL;

-- Patch 2: Add 'cvebaseinfo_cisakev' column to image_cves_v2
ALTER TABLE image_cves_v2 ADD COLUMN IF NOT EXISTS cvebaseinfo_cisakev boolean DEFAULT false;

-- Patch 3: Add 'cvebaseinfo_knownransomwarecampaign' column to image_cves_v2
ALTER TABLE image_cves_v2 ADD COLUMN IF NOT EXISTS cvebaseinfo_knownransomwarecampaign boolean DEFAULT false;

-- Patch 4: Add 'origin' column to image_cves_v2 (CVE origin / source tracker)
ALTER TABLE image_cves_v2 ADD COLUMN IF NOT EXISTS origin integer DEFAULT 0;
```

## Verification

After applying patches, verify columns exist:

```sql
-- Check report_snapshots.type
SELECT column_name, data_type, column_default
FROM information_schema.columns
WHERE table_name = 'report_snapshots' AND column_name = 'type';

-- Check image_cves_v2 new columns
SELECT column_name, data_type, column_default
FROM information_schema.columns
WHERE table_name = 'image_cves_v2'
  AND column_name IN ('cvebaseinfo_cisakev', 'cvebaseinfo_knownransomwarecampaign', 'origin');
```

Expected: 4 rows returned (one for each added column).

## Revert (if needed)

If the stock RHACS operator redeploys Central and the migrator fails because
the columns already exist, these statements will remove them:

```sql
-- Revert Patch 1
ALTER TABLE report_snapshots DROP COLUMN IF EXISTS type;

-- Revert Patch 2
ALTER TABLE image_cves_v2 DROP COLUMN IF EXISTS cvebaseinfo_cisakev;

-- Revert Patch 3
ALTER TABLE image_cves_v2 DROP COLUMN IF EXISTS cvebaseinfo_knownransomwarecampaign;

-- Revert Patch 4
ALTER TABLE image_cves_v2 DROP COLUMN IF EXISTS origin;
```

**Note:** Reverting is unlikely to be necessary. The stock RHACS Central expects
these columns to exist (they're part of its schema). Adding them early is
consistent with the target state. The migrator uses GORM's `CreateTableFromModel`
which handles "column already exists" gracefully via AutoMigrate.

## When This Becomes Unnecessary

These patches become unnecessary if:
1. The DB version trick is removed (seq_num matches the actual binary version)
2. The stock RHACS operator runs and its migrator brings the DB to the correct version
3. The custom build's schema version catches up past 227

## Applying via oc exec

```bash
# Get the Central DB pod and password
DB_POD=$(oc get pods -n rhacs-operator -l app=central-db -o jsonpath='{.items[0].metadata.name}')
DB_PASS=$(oc get secret central-db-password -n rhacs-operator -o jsonpath='{.data.password}' | base64 -d)

# Run the patches
oc exec -n rhacs-operator "$DB_POD" -c central-db -- bash -c "PGPASSWORD=$DB_PASS psql -U postgres -d central_active -c \"
  ALTER TABLE report_snapshots ADD COLUMN IF NOT EXISTS type integer DEFAULT 0;
  UPDATE report_snapshots SET type = 0 WHERE type IS NULL;
  ALTER TABLE image_cves_v2 ADD COLUMN IF NOT EXISTS cvebaseinfo_cisakev boolean DEFAULT false;
  ALTER TABLE image_cves_v2 ADD COLUMN IF NOT EXISTS cvebaseinfo_knownransomwarecampaign boolean DEFAULT false;
  ALTER TABLE image_cves_v2 ADD COLUMN IF NOT EXISTS origin integer DEFAULT 0;
\""

# Verify
oc exec -n rhacs-operator "$DB_POD" -c central-db -- bash -c "PGPASSWORD=$DB_PASS psql -U postgres -d central_active -c \"
  SELECT table_name, column_name, data_type FROM information_schema.columns
  WHERE (table_name = 'report_snapshots' AND column_name = 'type')
     OR (table_name = 'image_cves_v2' AND column_name IN ('cvebaseinfo_cisakev', 'cvebaseinfo_knownransomwarecampaign', 'origin'));
\""
```

## Applied On

- **Date**: 2026-09-30
- **Cluster**: api.aromerot.redhat-openshift.com:6443
- **Namespace**: rhacs-operator
- **DB Pod**: central-db-66bb9f47c8-85lmd
- **Result**: All 4 columns added successfully, verified via information_schema
