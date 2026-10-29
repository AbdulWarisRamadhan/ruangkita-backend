package main

import (
	"strings"
	"testing"
)

func TestMigrationSQL(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		want      string
		wantError bool
	}{
		{
			name:      "file kosong",
			input:     " \n\t ",
			wantError: true,
		},
		{
			name:      "transaksi tanpa isi",
			input:     "BEGIN;\n\nCOMMIT;",
			wantError: true,
		},
		{
			name:  "menghapus pembungkus transaksi",
			input: "BEGIN;\nCREATE TABLE example (id BIGINT);\nCOMMIT;",
			want:  "CREATE TABLE example (id BIGINT);",
		},
		{
			name:  "SQL tanpa pembungkus transaksi",
			input: "CREATE TABLE example (id BIGINT);",
			want:  "CREATE TABLE example (id BIGINT);",
		},
		{
			name:  "mempertahankan beberapa perintah SQL",
			input: "BEGIN;\nCREATE TABLE example (id BIGINT);\nCREATE INDEX idx_example_id ON example (id);\nCOMMIT;",
			want:  "CREATE TABLE example (id BIGINT);\nCREATE INDEX idx_example_id ON example (id);",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := migrationSQL(tt.input)

			if tt.wantError {
				if err == nil {
					t.Fatal("mengharapkan error, tetapi tidak mendapatkannya")
				}
				return
			}

			if err != nil {
				t.Fatalf("error tidak diharapkan: %v", err)
			}

			if strings.TrimSpace(got) != tt.want {
				t.Errorf("hasil:\n%q\n\nharapan:\n%q", got, tt.want)
			}
		})
	}
}
