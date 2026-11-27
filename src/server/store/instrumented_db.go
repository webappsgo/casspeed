package store

import (
	"context"
	"database/sql"
	"regexp"
	"strings"
	"time"

	"github.com/casapps/casspeed/src/metrics"
)

var sqlTableName = regexp.MustCompile(`(?i)\b(?:FROM|INTO|UPDATE|JOIN|TABLE)\s+([a-z_][a-z0-9_]*)`)

type instrumentedDB struct {
	*sql.DB
}

func (db *instrumentedDB) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	started := time.Now()
	result, err := db.DB.ExecContext(ctx, query, args...)
	recordDatabaseCall(query, started, err)
	return result, err
}

func (db *instrumentedDB) QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	started := time.Now()
	rows, err := db.DB.QueryContext(ctx, query, args...)
	recordDatabaseCall(query, started, err)
	return rows, err
}

func (db *instrumentedDB) QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row {
	started := time.Now()
	row := db.DB.QueryRowContext(ctx, query, args...)
	recordDatabaseCall(query, started, row.Err())
	return row
}

func recordDatabaseCall(query string, started time.Time, err error) {
	operation := "other"
	if fields := strings.Fields(query); len(fields) > 0 {
		operation = strings.ToLower(strings.Trim(fields[0], "(;"))
	}
	table := "unknown"
	if match := sqlTableName.FindStringSubmatch(query); len(match) == 2 {
		table = strings.ToLower(match[1])
	}
	errorType := ""
	if err != nil {
		errorType = "other"
		if isSQLiteBusy(err) {
			errorType = "busy"
		}
	}
	duration := time.Since(started).Seconds()
	metrics.RecordDatabase(operation, table, errorType, duration)
}

func isSQLiteBusy(err error) bool {
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "database is locked") || strings.Contains(message, "database is busy") || strings.Contains(message, "sqlite_busy") || strings.Contains(message, "sqlite_locked")
}
