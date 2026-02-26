package icmprepo

import (
	"bufio"
	"bytes"
	"database/sql"
	"encoding/csv"
	"errors"
	"fmt"
	"math"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	_ "modernc.org/sqlite"
)

const defaultMaxHosts = 20000

type Repo struct {
	readDB   *sql.DB
	writeDB  *sql.DB
	maxHosts int
}

type HostSummary struct {
	ID            int64  `json:"id"`
	Name          string `json:"name"`
	IP            string `json:"ip"`
	Group         string `json:"group"`
	Subgroup      string `json:"subgroup"`
	Status        string `json:"st"`
	IntervalMS    int    `json:"interval_ms"`
	TimeoutMS     int    `json:"timeout_ms"`
	DownThreshold int    `json:"down_threshold"`
	Enabled       bool   `json:"enabled"`
	Fail          int64  `json:"fail"`
}

type HostDetail struct {
	HostSummary
	OK           int64    `json:"ok"`
	Last         int      `json:"last"`
	Avg          int      `json:"avg"`
	Min          int      `json:"min"`
	Max          int      `json:"max"`
	SamplesCount int64    `json:"samples_count"`
	Samples      []Sample `json:"samples"`
}

type Sample struct {
	TS  int64 `json:"ts"`
	RTT int   `json:"rtt"`
}

type Event struct {
	TS        int64  `json:"ts"`
	OldStatus int    `json:"old_status"`
	NewStatus int    `json:"new_status"`
	Detail    string `json:"detail"`
}

type HostInput struct {
	Name          string
	IP            string
	Group         string
	Subgroup      string
	IntervalMS    int
	TimeoutMS     int
	DownThreshold int
	Enabled       bool
}

type CSVImportDetail struct {
	Line   int    `json:"line"`
	Host   string `json:"host"`
	Reason string `json:"reason"`
}

type CSVImportStats struct {
	Added              int               `json:"-"`
	Updated            int               `json:"updated"`
	Bad                int               `json:"bad"`
	DuplicatesExisting int               `json:"duplicates_existing"`
	DuplicatesFile     int               `json:"duplicates_file"`
	Details            []CSVImportDetail `json:"details"`
}

func New(path string) (*Repo, error) {
	if path == "" {
		return nil, errors.New("empty sqlite path")
	}
	dsn := path
	if path != ":memory:" && !strings.HasPrefix(path, "file:") {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return nil, err
		}
		dsn = "file:" + filepath.ToSlash(path)
	}
	if strings.HasPrefix(path, "file:") {
		dsn = path
	}

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	readDB, err := sql.Open("sqlite", dsn)
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	readDB.SetMaxOpenConns(1)
	readDB.SetMaxIdleConns(1)

	repo := &Repo{
		readDB:   readDB,
		writeDB:  db,
		maxHosts: defaultMaxHosts,
	}
	if err := repo.initWrite(); err != nil {
		_ = readDB.Close()
		_ = db.Close()
		return nil, err
	}
	if err := repo.initRead(); err != nil {
		_ = readDB.Close()
		_ = db.Close()
		return nil, err
	}
	return repo, nil
}

func (r *Repo) initWrite() error {
	statements := []string{
		`PRAGMA journal_mode=WAL;`,
		`PRAGMA busy_timeout=5000;`,
		`PRAGMA foreign_keys=OFF;`,
		`CREATE TABLE IF NOT EXISTS hosts(
			host_id INTEGER PRIMARY KEY,
			name TEXT,
			ip TEXT,
			grp TEXT,
			subgrp TEXT,
			interval_ms INTEGER,
			timeout_ms INTEGER,
			down_threshold INTEGER,
			enabled INTEGER
		);`,
		`CREATE TABLE IF NOT EXISTS samples(
			ts INTEGER,
			host_id INTEGER,
			rtt_ms INTEGER NULL,
			timeout_ms INTEGER
		);`,
		`CREATE TABLE IF NOT EXISTS events(
			ts INTEGER,
			host_id INTEGER,
			old_status INTEGER,
			new_status INTEGER,
			detail TEXT
		);`,
		`CREATE INDEX IF NOT EXISTS idx_hosts_grp_sub ON hosts(grp, subgrp, host_id);`,
		`CREATE INDEX IF NOT EXISTS idx_samples_host_ts ON samples(host_id, ts);`,
		`CREATE INDEX IF NOT EXISTS idx_samples_host_rtt ON samples(host_id, rtt_ms);`,
		`CREATE INDEX IF NOT EXISTS idx_events_host_ts ON events(host_id, ts);`,
	}
	for _, stmt := range statements {
		if _, err := r.writeDB.Exec(stmt); err != nil {
			return err
		}
	}
	return nil
}

func (r *Repo) initRead() error {
	statements := []string{
		`PRAGMA journal_mode=WAL;`,
		`PRAGMA busy_timeout=5000;`,
		`PRAGMA foreign_keys=OFF;`,
	}
	for _, stmt := range statements {
		if _, err := r.readDB.Exec(stmt); err != nil {
			return err
		}
	}
	return nil
}

func (r *Repo) ListHosts() ([]HostSummary, error) {
	rows, err := r.readDB.Query(`
		SELECT
			h.host_id,
			COALESCE(h.name, ''),
			COALESCE(h.ip, ''),
			COALESCE(h.grp, 'Default'),
			COALESCE(h.subgrp, 'Main'),
			COALESCE(h.interval_ms, 1000),
			COALESCE(h.timeout_ms, 1000),
			COALESCE(h.down_threshold, 3),
			COALESCE(h.enabled, 1),
			COALESCE((SELECT e.new_status FROM events e WHERE e.host_id = h.host_id ORDER BY e.ts DESC, rowid DESC LIMIT 1), 0) AS last_status,
			0 AS fail_count
		FROM hosts h
		ORDER BY COALESCE(h.grp, 'Default'), COALESCE(h.subgrp, 'Main'), h.host_id
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []HostSummary
	for rows.Next() {
		var item HostSummary
		var enabled int
		var st int
		if err := rows.Scan(
			&item.ID,
			&item.Name,
			&item.IP,
			&item.Group,
			&item.Subgroup,
			&item.IntervalMS,
			&item.TimeoutMS,
			&item.DownThreshold,
			&enabled,
			&st,
			&item.Fail,
		); err != nil {
			return nil, err
		}
		item.Enabled = enabled != 0
		item.Status = mapStatus(st)
		out = append(out, item)
	}
	return out, nil
}

func (r *Repo) GetHost(id int64, sampleLimit int) (*HostDetail, error) {
	var h HostDetail
	var enabled int
	var st int
	err := r.readDB.QueryRow(`
		SELECT
			h.host_id,
			COALESCE(h.name, ''),
			COALESCE(h.ip, ''),
			COALESCE(h.grp, 'Default'),
			COALESCE(h.subgrp, 'Main'),
			COALESCE(h.interval_ms, 1000),
			COALESCE(h.timeout_ms, 1000),
			COALESCE(h.down_threshold, 3),
			COALESCE(h.enabled, 1),
			COALESCE((SELECT e.new_status FROM events e WHERE e.host_id = h.host_id ORDER BY e.ts DESC, rowid DESC LIMIT 1), 0),
			COALESCE((SELECT COUNT(*) FROM samples s WHERE s.host_id = h.host_id AND s.rtt_ms IS NULL), 0)
		FROM hosts h
		WHERE h.host_id = ?
	`, id).Scan(
		&h.ID,
		&h.Name,
		&h.IP,
		&h.Group,
		&h.Subgroup,
		&h.IntervalMS,
		&h.TimeoutMS,
		&h.DownThreshold,
		&enabled,
		&st,
		&h.Fail,
	)
	if err != nil {
		return nil, err
	}
	h.Enabled = enabled != 0
	h.Status = mapStatus(st)

	var ok sql.NullInt64
	var fail sql.NullInt64
	var total sql.NullInt64
	var min sql.NullInt64
	var max sql.NullInt64
	var avg sql.NullFloat64
	if err := r.readDB.QueryRow(`
		SELECT
			SUM(CASE WHEN rtt_ms IS NOT NULL THEN 1 ELSE 0 END) AS ok_count,
			SUM(CASE WHEN rtt_ms IS NULL THEN 1 ELSE 0 END) AS fail_count,
			COUNT(*) AS total_count,
			MIN(CASE WHEN rtt_ms IS NOT NULL THEN rtt_ms END) AS min_rtt,
			MAX(CASE WHEN rtt_ms IS NOT NULL THEN rtt_ms END) AS max_rtt,
			AVG(CASE WHEN rtt_ms IS NOT NULL THEN rtt_ms END) AS avg_rtt
		FROM samples
		WHERE host_id = ?
	`, id).Scan(&ok, &fail, &total, &min, &max, &avg); err != nil {
		return nil, err
	}
	h.OK = nullInt64(ok)
	h.Fail = nullInt64(fail)
	h.SamplesCount = nullInt64(total)
	h.Min = int(nullInt64(min))
	h.Max = int(nullInt64(max))
	if avg.Valid {
		h.Avg = int(math.Round(avg.Float64))
	}

	var last sql.NullInt64
	if err := r.readDB.QueryRow(`
		SELECT rtt_ms
		FROM samples
		WHERE host_id = ?
		ORDER BY ts DESC, rowid DESC
		LIMIT 1
	`, id).Scan(&last); err == nil {
		if last.Valid {
			h.Last = int(last.Int64)
		} else {
			h.Last = -1
		}
	}

	if sampleLimit <= 0 {
		sampleLimit = 2000
	}
	samples, err := r.ListSamples(id, nil, nil, sampleLimit)
	if err != nil {
		return nil, err
	}
	h.Samples = samples

	return &h, nil
}

func (r *Repo) ListSamples(hostID int64, fromTS, toTS *int64, limit int) ([]Sample, error) {
	if limit <= 0 {
		limit = 2000
	}
	var (
		rows *sql.Rows
		err  error
	)

	if fromTS == nil && toTS == nil {
		// For live UI we need the latest points, but rendered in chronological order.
		rows, err = r.readDB.Query(`
			SELECT ts, COALESCE(rtt_ms, -1) AS rtt
			FROM (
				SELECT ts, rtt_ms, rowid
				FROM samples
				WHERE host_id = ?
				ORDER BY ts DESC, rowid DESC
				LIMIT ?
			)
			ORDER BY ts, rowid
		`, hostID, limit)
	} else {
		rows, err = r.readDB.Query(`
			SELECT ts, COALESCE(rtt_ms, -1) AS rtt
			FROM samples
			WHERE host_id = ?
			  AND (? IS NULL OR ts >= ?)
			  AND (? IS NULL OR ts <= ?)
			ORDER BY ts, rowid
			LIMIT ?
		`, hostID, fromTS, fromTS, toTS, toTS, limit)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Sample
	for rows.Next() {
		var s Sample
		if err := rows.Scan(&s.TS, &s.RTT); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, nil
}

func (r *Repo) ListEvents(hostID int64, fromTS, toTS *int64, limit int) ([]Event, error) {
	if limit <= 0 {
		limit = 200
	}
	rows, err := r.readDB.Query(`
		SELECT ts, old_status, new_status, COALESCE(detail, '')
		FROM events
		WHERE host_id = ?
		  AND (? IS NULL OR ts >= ?)
		  AND (? IS NULL OR ts <= ?)
		ORDER BY ts DESC
		LIMIT ?
	`, hostID, fromTS, fromTS, toTS, toTS, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Event
	for rows.Next() {
		var e Event
		if err := rows.Scan(&e.TS, &e.OldStatus, &e.NewStatus, &e.Detail); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, nil
}

func (r *Repo) ExportHostsCSV() ([]byte, error) {
	rows, err := r.readDB.Query(`
		SELECT
			COALESCE(grp, 'Default'),
			COALESCE(subgrp, 'Main'),
			COALESCE(name, ''),
			COALESCE(interval_ms, 1000),
			COALESCE(timeout_ms, 1000),
			COALESCE(down_threshold, 3),
			COALESCE(enabled, 1)
		FROM hosts
		ORDER BY COALESCE(grp, 'Default'), COALESCE(subgrp, 'Main'), host_id
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	w.UseCRLF = true
	if err := w.Write([]string{"group", "subgroup", "host", "interval_ms", "timeout_ms", "down_threshold", "enabled"}); err != nil {
		return nil, err
	}

	for rows.Next() {
		var (
			group         string
			subgroup      string
			host          string
			intervalMS    int
			timeoutMS     int
			downThreshold int
			enabled       int
		)
		if err := rows.Scan(&group, &subgroup, &host, &intervalMS, &timeoutMS, &downThreshold, &enabled); err != nil {
			return nil, err
		}
		rec := []string{
			group,
			subgroup,
			host,
			strconv.Itoa(intervalMS),
			strconv.Itoa(timeoutMS),
			strconv.Itoa(downThreshold),
			strconv.Itoa(enabled),
		}
		if err := w.Write(rec); err != nil {
			return nil, err
		}
	}
	w.Flush()
	if err := w.Error(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (r *Repo) PreviewImportCSV(body string) (CSVImportStats, error) {
	return r.processImportCSV(body, true)
}

func (r *Repo) ImportCSV(body string) (CSVImportStats, error) {
	return r.processImportCSV(body, false)
}

func (r *Repo) processImportCSV(body string, previewOnly bool) (CSVImportStats, error) {
	const maxDetails = 200
	stats := CSVImportStats{
		Details: make([]CSVImportDetail, 0, maxDetails),
	}
	seenNames := map[string]struct{}{}
	seenIPs := map[string]struct{}{}

	sc := bufio.NewScanner(strings.NewReader(body))
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)

	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(sc.Text())
		if lineNo == 1 {
			line = strings.TrimPrefix(line, "\uFEFF")
		}
		if line == "" {
			continue
		}
		if isCSVHeaderLine(line) {
			continue
		}

		delim := ','
		if strings.Contains(line, ";") && !strings.Contains(line, ",") {
			delim = ';'
		}
		fields, err := parseCSVLine(line, delim)
		if err != nil || len(fields) < 3 {
			stats.Bad++
			appendCSVImportDetail(&stats, maxDetails, lineNo, "", "invalid columns")
			continue
		}

		host := strings.TrimSpace(fields[2])
		if host == "" {
			stats.Bad++
			appendCSVImportDetail(&stats, maxDetails, lineNo, "", "invalid columns")
			continue
		}

		ip, err := resolveHostOrIP(host)
		if err != nil {
			stats.Bad++
			appendCSVImportDetail(&stats, maxDetails, lineNo, host, "resolve failed")
			continue
		}

		nameKey := strings.ToLower(host)
		if _, ok := seenNames[nameKey]; ok {
			stats.DuplicatesFile++
			appendCSVImportDetail(&stats, maxDetails, lineNo, host, "duplicate inside file")
			continue
		}
		if _, ok := seenIPs[ip]; ok {
			stats.DuplicatesFile++
			appendCSVImportDetail(&stats, maxDetails, lineNo, host, "duplicate inside file")
			continue
		}

		seenNames[nameKey] = struct{}{}
		seenIPs[ip] = struct{}{}

		group := readCSVField(fields, 0, "Default")
		subgroup := readCSVField(fields, 1, "Main")
		interval := parseCSVIntField(fields, 3, 1000)
		timeout := parseCSVIntField(fields, 4, 1000)
		downThreshold := parseCSVIntField(fields, 5, 3)
		enabled := parseCSVEnabledField(readCSVField(fields, 6, "1"), true)

		existingID, exists, err := r.findHostIDByNameOrIP(host, ip)
		if err != nil {
			return stats, err
		}
		if exists {
			if previewOnly {
				stats.Updated++
				continue
			}
			if err := r.UpdateHost(existingID, HostInput{
				Name:          host,
				IP:            ip,
				Group:         group,
				Subgroup:      subgroup,
				IntervalMS:    interval,
				TimeoutMS:     timeout,
				DownThreshold: downThreshold,
				Enabled:       enabled,
			}); err != nil {
				stats.Bad++
				appendCSVImportDetail(&stats, maxDetails, lineNo, host, "cannot update")
			} else {
				stats.Updated++
			}
			continue
		}

		if previewOnly {
			stats.Added++
			continue
		}

		_, err = r.AddHost(HostInput{
			Name:          host,
			IP:            ip,
			Group:         group,
			Subgroup:      subgroup,
			IntervalMS:    interval,
			TimeoutMS:     timeout,
			DownThreshold: downThreshold,
			Enabled:       enabled,
		})
		if err != nil {
			if strings.Contains(strings.ToLower(err.Error()), "already exists") {
				stats.DuplicatesExisting++
				appendCSVImportDetail(&stats, maxDetails, lineNo, host, "already exists")
			} else {
				stats.Bad++
				appendCSVImportDetail(&stats, maxDetails, lineNo, host, "cannot add")
			}
			continue
		}
		stats.Added++
	}
	if err := sc.Err(); err != nil {
		return stats, err
	}

	return stats, nil
}

func (r *Repo) AddHost(input HostInput) (int64, error) {
	in, err := normalizeHostInput(input)
	if err != nil {
		return 0, err
	}

	tx, err := r.writeDB.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	if exists, err := hostExists(tx, in.Name, in.IP, 0); err != nil {
		return 0, err
	} else if exists {
		return 0, errors.New("host already exists")
	}

	id, err := firstFreeHostID(tx, r.maxHosts)
	if err != nil {
		return 0, err
	}
	_, err = tx.Exec(`
		INSERT INTO hosts(host_id, name, ip, grp, subgrp, interval_ms, timeout_ms, down_threshold, enabled)
		VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, id, in.Name, in.IP, in.Group, in.Subgroup, in.IntervalMS, in.TimeoutMS, in.DownThreshold, boolToInt(in.Enabled))
	if err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return id, nil
}

func (r *Repo) UpdateHost(id int64, input HostInput) error {
	in, err := normalizeHostInput(input)
	if err != nil {
		return err
	}

	tx, err := r.writeDB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if exists, err := hostExists(tx, in.Name, in.IP, id); err != nil {
		return err
	} else if exists {
		return errors.New("host already exists")
	}

	result, err := tx.Exec(`
		UPDATE hosts
		SET name = ?, ip = ?, grp = ?, subgrp = ?, interval_ms = ?, timeout_ms = ?, down_threshold = ?, enabled = ?
		WHERE host_id = ?
	`, in.Name, in.IP, in.Group, in.Subgroup, in.IntervalMS, in.TimeoutMS, in.DownThreshold, boolToInt(in.Enabled), id)
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return sql.ErrNoRows
	}
	return tx.Commit()
}

func (r *Repo) DeleteHost(id int64) error {
	tx, err := r.writeDB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := tx.Exec(`DELETE FROM events WHERE host_id = ?`, id); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM samples WHERE host_id = ?`, id); err != nil {
		return err
	}
	result, err := tx.Exec(`DELETE FROM hosts WHERE host_id = ?`, id)
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return sql.ErrNoRows
	}
	return tx.Commit()
}

func normalizeHostInput(input HostInput) (HostInput, error) {
	in := input
	in.Name = strings.TrimSpace(in.Name)
	in.IP = strings.TrimSpace(in.IP)
	in.Group = strings.TrimSpace(in.Group)
	in.Subgroup = strings.TrimSpace(in.Subgroup)

	if in.Name == "" {
		return in, errors.New("name is required")
	}
	if in.Group == "" {
		in.Group = "Default"
	}
	if in.Subgroup == "" {
		in.Subgroup = "Main"
	}

	ip := net.ParseIP(in.IP)
	if ip == nil && in.IP == "" {
		resolved, err := resolveIPv4(in.Name)
		if err != nil {
			return in, errors.New("cannot resolve host")
		}
		in.IP = resolved
	} else if ip != nil {
		if v4 := ip.To4(); v4 != nil {
			in.IP = v4.String()
		}
	}
	if net.ParseIP(in.IP) == nil {
		return in, errors.New("invalid ip")
	}

	if in.IntervalMS <= 0 {
		in.IntervalMS = 1000
	}
	if in.TimeoutMS <= 0 {
		in.TimeoutMS = 1000
	}
	if in.DownThreshold <= 0 {
		in.DownThreshold = 3
	}
	if in.IntervalMS < 50 {
		in.IntervalMS = 50
	}
	if in.TimeoutMS < 50 {
		in.TimeoutMS = 50
	}
	if in.DownThreshold < 1 {
		in.DownThreshold = 1
	}

	return in, nil
}

func resolveIPv4(host string) (string, error) {
	ips, err := net.LookupIP(host)
	if err != nil {
		return "", err
	}
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil {
			return v4.String(), nil
		}
	}
	return "", errors.New("no ipv4 address")
}

func hostExists(tx *sql.Tx, name, ip string, exceptID int64) (bool, error) {
	var found int64
	err := tx.QueryRow(`
		SELECT host_id
		FROM hosts
		WHERE (lower(name) = lower(?) OR ip = ?)
		  AND (? = 0 OR host_id <> ?)
		LIMIT 1
	`, name, ip, exceptID, exceptID).Scan(&found)
	if err == sql.ErrNoRows {
		return false, nil
	}
	return err == nil, err
}

func firstFreeHostID(tx *sql.Tx, maxID int) (int64, error) {
	rows, err := tx.Query(`SELECT host_id FROM hosts WHERE host_id BETWEEN 1 AND ? ORDER BY host_id`, maxID)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	expect := int64(1)
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return 0, err
		}
		if id > expect {
			break
		}
		if id == expect {
			expect++
		}
	}
	if expect > int64(maxID) {
		return 0, fmt.Errorf("host capacity reached (%d)", maxID)
	}
	return expect, nil
}

func mapStatus(status int) string {
	switch status {
	case 1:
		return "UP"
	case 2:
		return "DOWN"
	default:
		return "UNKNOWN"
	}
}

func nullInt64(v sql.NullInt64) int64 {
	if v.Valid {
		return v.Int64
	}
	return 0
}

func boolToInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

func (r *Repo) findHostIDByNameOrIP(name, ip string) (int64, bool, error) {
	var found int64
	err := r.readDB.QueryRow(`
		SELECT host_id
		FROM hosts
		WHERE lower(name) = lower(?)
		   OR ip = ?
		ORDER BY CASE WHEN lower(name) = lower(?) THEN 0 ELSE 1 END, host_id
		LIMIT 1
	`, name, ip, name).Scan(&found)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, false, nil
	}
	return found, err == nil, err
}

func resolveHostOrIP(host string) (string, error) {
	host = strings.TrimSpace(host)
	if host == "" {
		return "", errors.New("empty host")
	}
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			return v4.String(), nil
		}
		return "", errors.New("invalid ipv4")
	}
	return resolveIPv4(host)
}

func isCSVHeaderLine(line string) bool {
	s := strings.ToLower(strings.TrimSpace(line))
	return strings.HasPrefix(s, "group,") || strings.HasPrefix(s, "group;")
}

func parseCSVLine(line string, delim rune) ([]string, error) {
	reader := csv.NewReader(strings.NewReader(line))
	reader.FieldsPerRecord = -1
	reader.TrimLeadingSpace = true
	reader.Comma = delim
	return reader.Read()
}

func readCSVField(fields []string, idx int, fallback string) string {
	if idx >= len(fields) {
		return fallback
	}
	v := strings.TrimSpace(fields[idx])
	if v == "" {
		return fallback
	}
	return v
}

func parseCSVIntField(fields []string, idx int, fallback int) int {
	if idx >= len(fields) {
		return fallback
	}
	v := strings.TrimSpace(fields[idx])
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return fallback
	}
	return n
}

func parseCSVEnabledField(value string, fallback bool) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	case "":
		return fallback
	default:
		return fallback
	}
}

func appendCSVImportDetail(stats *CSVImportStats, maxDetails, line int, host, reason string) {
	if len(stats.Details) >= maxDetails {
		return
	}
	stats.Details = append(stats.Details, CSVImportDetail{
		Line:   line,
		Host:   host,
		Reason: reason,
	})
}
