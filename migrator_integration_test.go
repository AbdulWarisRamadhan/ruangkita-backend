package main

import (
	"database/sql"
	"os"
	"testing"
	"time"
)

func TestRunMigrationsIntegration(t *testing.T) {
	if os.Getenv("RUANGKITA_RUN_MIGRATION_INTEGRATION") != "1" {
		t.Skip("set RUANGKITA_RUN_MIGRATION_INTEGRATION=1 untuk menjalankan pengujian integrasi")
	}

	const allowedDatabase = "ruangkita_v4_migration_test"
	if os.Getenv("DB_NAME") != allowedDatabase {
		t.Fatalf("pengujian hanya boleh menggunakan database %q", allowedDatabase)
	}

	dsn, err := databaseDSN()
	if err != nil {
		t.Fatalf("konfigurasi koneksi: %v", err)
	}

	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("membuka database: %v", err)
	}
	defer db.Close()

	db.SetMaxOpenConns(2)
	db.SetConnMaxLifetime(time.Minute)
	if err := db.Ping(); err != nil {
		t.Fatalf("menghubungi database pengujian: %v", err)
	}

	var actualDatabase string
	if err := db.QueryRow("SELECT current_database()").Scan(&actualDatabase); err != nil {
		t.Fatalf("memastikan database aktif: %v", err)
	}
	if actualDatabase != allowedDatabase {
		t.Fatalf("database aktif %q tidak diizinkan", actualDatabase)
	}

	// Pengujian ini tidak menghapus atau mengatur ulang database.
	// Hanya database pengujian yang masih kosong yang boleh dipakai.
	var existingTables int
	if err := db.QueryRow(`
        SELECT count(*) FROM information_schema.tables
        WHERE table_schema = 'public' AND table_type = 'BASE TABLE'
    `).Scan(&existingTables); err != nil {
		t.Fatalf("memeriksa tabel awal: %v", err)
	}
	if existingTables != 0 {
		t.Fatalf("database pengujian tidak kosong (%d tabel); tidak menjalankan migrasi", existingTables)
	}

	if err := runMigrations(db); err != nil {
		t.Fatalf("migrasi pertama gagal: %v", err)
	}

	for _, tableName := range []string{"users", "sessions", "messages", "schema_migrations"} {
		var exists bool
		if err := db.QueryRow(`
            SELECT EXISTS (
                SELECT 1 FROM information_schema.tables
                WHERE table_schema = 'public' AND table_name = $1
            )
        `, tableName).Scan(&exists); err != nil {
			t.Fatalf("memeriksa tabel %s: %v", tableName, err)
		}
		if !exists {
			t.Errorf("tabel %s tidak dibuat", tableName)
		}
	}

	var migrationCount int
	if err := db.QueryRow("SELECT count(*) FROM schema_migrations WHERE version = $1", "001_base_schema").Scan(&migrationCount); err != nil {
		t.Fatalf("memeriksa riwayat migrasi: %v", err)
	}
	if migrationCount != 1 {
		t.Fatalf("versi 001_base_schema tercatat %d kali; diharapkan 1", migrationCount)
	}

	if err := runMigrations(db); err != nil {
		t.Fatalf("migrasi kedua gagal: %v", err)
	}

	if err := db.QueryRow("SELECT count(*) FROM schema_migrations WHERE version = $1", "001_base_schema").Scan(&migrationCount); err != nil {
		t.Fatalf("memeriksa riwayat setelah migrasi kedua: %v", err)
	}
	if migrationCount != 1 {
		t.Fatalf("versi 001_base_schema tercatat %d kali setelah pengulangan; diharapkan 1", migrationCount)
	}
}
