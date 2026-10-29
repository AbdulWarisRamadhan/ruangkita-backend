package main

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"io/fs"
	"log"
	"path"
	"regexp"
	"sort"
	"strings"
	"time"
)

//go:embed migrations/*.sql
var migrationFiles embed.FS

var migrationNamePattern = regexp.MustCompile(`^[0-9]+_[a-z0-9_]+$`)

func migrationSQL(source string) (string, error) {
	source = strings.TrimSpace(source)
	if source == "" {
		return "", fmt.Errorf("file migrasi kosong")
	}

	parts := strings.Split(source, "\n")
	if len(parts) >= 2 &&
		strings.TrimSpace(parts[0]) == "BEGIN;" &&
		strings.TrimSpace(parts[len(parts)-1]) == "COMMIT;" {
		statement := strings.TrimSpace(strings.Join(parts[1:len(parts)-1], "\n"))
		if statement == "" {
			return "", fmt.Errorf("isi migrasi kosong")
		}
		return statement, nil
	}
	return source, nil
}

func runMigrations(db *sql.DB) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	conn, err := db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("membuka koneksi migrasi: %w", err)
	}
	defer conn.Close()

	const lockID int64 = 736219402
	if _, err := conn.ExecContext(ctx, "SELECT pg_advisory_lock($1)", lockID); err != nil {
		return fmt.Errorf("mengunci migrasi: %w", err)
	}
	defer func() {
		unlockCtx, unlockCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer unlockCancel()
		if _, err := conn.ExecContext(unlockCtx, "SELECT pg_advisory_unlock($1)", lockID); err != nil {
			log.Printf("Peringatan: gagal melepas kunci migrasi: %v", err)
		}
	}()

	_, err = conn.ExecContext(ctx, `
	CREATE TABLE IF NOT EXISTS schema_migrations (
		version VARCHAR(100) PRIMARY KEY,
				  applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
	)
	`)
	if err != nil {
		return fmt.Errorf("menyiapkan schema_migrations: %w", err)
	}

	entries, err := fs.Glob(migrationFiles, "migrations/*.sql")
	if err != nil {
		return fmt.Errorf("membaca daftar migrasi: %w", err)
	}
	sort.Strings(entries)
	if len(entries) == 0 {
		return fmt.Errorf("tidak ada file migrasi")
	}

	for _, filename := range entries {
		version := strings.TrimSuffix(path.Base(filename), ".sql")
		if !migrationNamePattern.MatchString(version) {
			return fmt.Errorf("nama migrasi tidak valid: %s", filename)
		}

		var applied bool
		err := conn.QueryRowContext(ctx,
			"SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version = $1)",
			version,
		).Scan(&applied)
		if err != nil {
			return fmt.Errorf("memeriksa migrasi %s: %w", version, err)
		}
		if applied {

			log.Printf("Migrasi %s sudah diterapkan", version)
			continue
		}

		data, err := migrationFiles.ReadFile(filename)
		if err != nil {
			return fmt.Errorf("membaca %s: %w", filename, err)
		}

		statement, err := migrationSQL(string(data))
		if err != nil {
			return fmt.Errorf("memproses %s: %w", filename, err)
		}

		tx, err := conn.BeginTx(ctx, nil)
		if err != nil {
			return fmt.Errorf("memulai transaksi %s: %w", version, err)
		}

		if _, err := tx.ExecContext(ctx, statement); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("menjalankan migrasi %s: %w", version, err)
		}

		if _, err := tx.ExecContext(ctx,
			"INSERT INTO schema_migrations (version) VALUES ($1)",
			version,
		); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("mencatat migrasi %s: %w", version, err)
		}

		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit migrasi %s: %w", version, err)
		}

		log.Printf("Migrasi %s berhasil", version)
	}

	return nil
}
