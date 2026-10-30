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

	const allowedDatabase = "ruangkita_v4_webpush_test"
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

	// Jangan pernah menghapus atau mengatur ulang tabel secara otomatis.
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

	var replyColumnExists bool
	if err := db.QueryRow(`
  SELECT EXISTS (
   SELECT 1 FROM information_schema.columns
   WHERE table_schema = 'public' AND table_name = 'messages'
     AND column_name = 'reply_to_message_id' AND data_type = 'bigint'
     AND is_nullable = 'YES'
  )
 `).Scan(&replyColumnExists); err != nil {
		t.Fatalf("memeriksa kolom reply: %v", err)
	}
	if !replyColumnExists {
		t.Error("kolom reply_to_message_id BIGINT NULL belum dibuat")
	}

	var foreignKeyExists bool
	if err := db.QueryRow(`
  SELECT EXISTS (
   SELECT 1 FROM pg_constraint c
   JOIN pg_class child ON child.oid = c.conrelid
   JOIN pg_namespace n ON n.oid = child.relnamespace
   JOIN pg_class parent ON parent.oid = c.confrelid
   JOIN pg_attribute attr ON attr.attrelid = child.oid AND attr.attnum = ANY(c.conkey)
   WHERE n.nspname = 'public' AND child.relname = 'messages'
     AND parent.relname = 'messages' AND attr.attname = 'reply_to_message_id'
     AND c.contype = 'f' AND c.confdeltype = 'n'
  )
 `).Scan(&foreignKeyExists); err != nil {
		t.Fatalf("memeriksa foreign key reply: %v", err)
	}
	if !foreignKeyExists {
		t.Error("foreign key reply menuju messages dengan ON DELETE SET NULL tidak ditemukan")
	}

	var indexExists bool
	if err := db.QueryRow(`
  SELECT EXISTS (
   SELECT 1 FROM pg_indexes
   WHERE schemaname = 'public' AND tablename = 'messages'
     AND indexname = 'idx_messages_reply_to'
  )
 `).Scan(&indexExists); err != nil {
		t.Fatalf("memeriksa indeks reply: %v", err)
	}
	if !indexExists {
		t.Error("indeks idx_messages_reply_to tidak ditemukan")
	}

	checkVersions := func(stage string) {
		t.Helper()
		for _, version := range []string{"001_base_schema", "002_message_replies"} {
			var count int
			if err := db.QueryRow(
				"SELECT count(*) FROM schema_migrations WHERE version = $1", version,
			).Scan(&count); err != nil {
				t.Fatalf("%s: memeriksa versi %s: %v", stage, version, err)
			}
			if count != 1 {
				t.Errorf("%s: versi %s tercatat %d kali; diharapkan 1", stage, version, count)
			}
		}
	}
	checkVersions("migrasi pertama")
	if err := runMigrations(db); err != nil {
		t.Fatalf("migrasi kedua gagal: %v", err)
	}
	checkVersions("migrasi kedua")
}
