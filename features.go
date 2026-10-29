package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const maxMediaBytes int64 = 20 << 20 // 20 MiB per file

func (a *App) ensureFeatures() error {
	statements := []string{
		`CREATE TABLE IF NOT EXISTS contacts (user_low BIGINT NOT NULL REFERENCES users(id), user_high BIGINT NOT NULL REFERENCES users(id), created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), PRIMARY KEY(user_low,user_high), CHECK(user_low < user_high))`,
		`CREATE TABLE IF NOT EXISTS contact_requests (id BIGSERIAL PRIMARY KEY, sender_id BIGINT NOT NULL REFERENCES users(id), receiver_id BIGINT NOT NULL REFERENCES users(id), status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','accepted','rejected')), created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), CHECK(sender_id <> receiver_id))`,
		`CREATE UNIQUE INDEX IF NOT EXISTS contact_requests_pending_pair ON contact_requests(LEAST(sender_id,receiver_id),GREATEST(sender_id,receiver_id)) WHERE status='pending'`,
		`CREATE TABLE IF NOT EXISTS media_files (id TEXT PRIMARY KEY, sender_id BIGINT NOT NULL REFERENCES users(id), receiver_id BIGINT NOT NULL REFERENCES users(id), original_name TEXT NOT NULL, mime_type TEXT NOT NULL, size_bytes BIGINT NOT NULL, view_once BOOLEAN NOT NULL DEFAULT FALSE, viewed_at TIMESTAMPTZ, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), expires_at TIMESTAMPTZ NOT NULL DEFAULT NOW() + INTERVAL '24 hours')`,
		`CREATE INDEX IF NOT EXISTS media_files_expires_idx ON media_files(expires_at)`,
		// Keep old conversations available to their two participants only.

	}
	for _, q := range statements {
		if _, err := a.db.Exec(q); err != nil {
			return fmt.Errorf("migrasi fitur: %w", err)
		}
	}
	// Backfill historical conversations exactly once, not on every restart.
	if _, err := a.db.Exec(`CREATE TABLE IF NOT EXISTS feature_migrations (name TEXT PRIMARY KEY)`); err != nil {
		return err
	}
	tx, err := a.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var inserted string
	err = tx.QueryRow(`INSERT INTO feature_migrations(name) VALUES('historical_contacts_v1') ON CONFLICT DO NOTHING RETURNING name`).Scan(&inserted)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if err == nil {
		_, err = tx.Exec(`INSERT INTO contacts(user_low,user_high) SELECT DISTINCT LEAST(sender_id::BIGINT,receiver_id::BIGINT),GREATEST(sender_id::BIGINT,receiver_id::BIGINT) FROM messages WHERE sender_id ~ '^[0-9]+$' AND receiver_id ~ '^[0-9]+$' AND sender_id <> receiver_id ON CONFLICT DO NOTHING`)
		if err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (a *App) areContacts(r *http.Request, left, right int64) (bool, error) {
    var ok bool

    err := a.db.QueryRowContext(
        r.Context(),
        `SELECT EXISTS(
            SELECT 1
            FROM contacts
            WHERE user_low = LEAST($1::BIGINT, $2::BIGINT)
              AND user_high = GREATEST($1::BIGINT, $2::BIGINT)
        )`,
        left,
        right,
    ).Scan(&ok)

    return ok, err
}

func (a *App) contacts(w http.ResponseWriter, r *http.Request, u *User) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	rows, err := a.db.QueryContext(r.Context(), `SELECT u.id,u.username,u.display_name,u.is_admin FROM contacts c JOIN users u ON u.id=CASE WHEN c.user_low=$1 THEN c.user_high ELSE c.user_low END WHERE (c.user_low=$1 OR c.user_high=$1) AND u.is_active=TRUE ORDER BY u.display_name`, u.ID)
	if err != nil {
		writeError(w, 500, "Gagal mengambil kontak")
		return
	}
	defer rows.Close()
	result := make([]User, 0)
	for rows.Next() {
		var item User
		if err := rows.Scan(&item.ID, &item.Username, &item.DisplayName, &item.IsAdmin); err != nil {
			writeError(w, 500, "Gagal membaca kontak")
			return
		}
		result = append(result, item)
	}
	if rows.Err() != nil {
		writeError(w, 500, "Gagal membaca kontak")
		return
	}
	writeJSON(w, 200, result)
}

func (a *App) contactSearch(w http.ResponseWriter, r *http.Request, u *User) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	name := strings.TrimSpace(r.URL.Query().Get("username"))
	if len(name) < 3 || len(name) > 50 {
		writeError(w, 400, "Masukkan username lengkap (3-50 karakter)")
		return
	}
	var found User
	err := a.db.QueryRowContext(r.Context(), `SELECT id,username,display_name,is_admin FROM users WHERE LOWER(username)=LOWER($1) AND is_active=TRUE AND id<>$2`, name, u.ID).Scan(&found.ID, &found.Username, &found.DisplayName, &found.IsAdmin)
	if errors.Is(err, sql.ErrNoRows) {
		writeError(w, 404, "Username tidak ditemukan")
		return
	}
	if err != nil {
		writeError(w, 500, "Gagal mencari pengguna")
		return
	}
	writeJSON(w, 200, found)
}

func (a *App) contactRequests(w http.ResponseWriter, r *http.Request, u *User) {
	switch r.Method {
	case http.MethodGet:
		rows, err := a.db.QueryContext(r.Context(), `SELECT cr.id,cr.sender_id,cr.receiver_id,cr.created_at,u.username,u.display_name FROM contact_requests cr JOIN users u ON u.id=cr.sender_id WHERE cr.receiver_id=$1 AND cr.status='pending' AND u.is_active=TRUE ORDER BY cr.id DESC`, u.ID)
		if err != nil {
			writeError(w, 500, "Gagal membaca permintaan")
			return
		}
		defer rows.Close()
		type item struct {
			ID          int64     `json:"id"`
			SenderID    int64     `json:"sender_id"`
			ReceiverID  int64     `json:"receiver_id"`
			CreatedAt   time.Time `json:"created_at"`
			Username    string    `json:"username"`
			DisplayName string    `json:"display_name"`
		}
		result := make([]item, 0)
		for rows.Next() {
			var v item
			if rows.Scan(&v.ID, &v.SenderID, &v.ReceiverID, &v.CreatedAt, &v.Username, &v.DisplayName) != nil {
				writeError(w, 500, "Gagal membaca permintaan")
				return
			}
			result = append(result, v)
		}
		if rows.Err() != nil {
			writeError(w, 500, "Gagal membaca permintaan")
			return
		}
		writeJSON(w, 200, result)
	case http.MethodPost:
		var input struct {
			Username string `json:"username"`
		}
		if decodeJSON(w, r, &input) != nil {
			writeError(w, 400, "JSON tidak valid")
			return
		}
		input.Username = strings.TrimSpace(input.Username)
		if len(input.Username) < 3 || len(input.Username) > 50 {
			writeError(w, 400, "Username tidak valid")
			return
		}
		var receiver int64
		err := a.db.QueryRowContext(r.Context(), `SELECT id FROM users WHERE LOWER(username)=LOWER($1) AND id<>$2 AND is_active=TRUE`, input.Username, u.ID).Scan(&receiver)
		if errors.Is(err, sql.ErrNoRows) {
			writeError(w, 404, "Pengguna tidak ditemukan")
			return
		}
		if err != nil {
			writeError(w, 500, "Gagal mencari pengguna")
			return
		}
		exists, err := a.areContacts(r, u.ID, receiver)
		if err != nil {
    		log.Printf("ERROR contactRequests areContacts: %v", err)
   			writeError(w, 500, "Gagal memeriksa kontak")
   			return
		}
		if exists {
			writeError(w, 409, "Sudah menjadi kontak")
			return
		}
		_, err = a.db.ExecContext(r.Context(), `INSERT INTO contact_requests(sender_id,receiver_id) VALUES($1,$2)`, u.ID, receiver)
		if err != nil {
			writeError(w, 409, "Permintaan kontak sudah ada")
			return
		}
		writeJSON(w, 201, map[string]string{"message": "Permintaan kontak terkirim"})
	default:
		methodNotAllowed(w)
	}
}

func (a *App) contactRespond(w http.ResponseWriter, r *http.Request, u *User) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	var input struct {
		RequestID int64 `json:"request_id"`
		Accept    bool  `json:"accept"`
	}
	if decodeJSON(w, r, &input) != nil || input.RequestID <= 0 {
		writeError(w, 400, "Permintaan tidak valid")
		return
	}
	tx, err := a.db.BeginTx(r.Context(), nil)
	if err != nil {
		writeError(w, 500, "Gagal memproses permintaan")
		return
	}
	defer tx.Rollback()
	var sender int64
	err = tx.QueryRowContext(r.Context(), `SELECT sender_id FROM contact_requests WHERE id=$1 AND receiver_id=$2 AND status='pending' FOR UPDATE`, input.RequestID, u.ID).Scan(&sender)
	if errors.Is(err, sql.ErrNoRows) {
		writeError(w, 404, "Permintaan tidak ditemukan")
		return
	}
	if err != nil {
		writeError(w, 500, "Gagal memproses permintaan")
		return
	}
	status := "rejected"
	if input.Accept {
    status = "accepted"

    if _, err = tx.ExecContext(
        r.Context(),
        `INSERT INTO contacts(user_low, user_high)
         VALUES(
             LEAST($1::BIGINT, $2::BIGINT),
             GREATEST($1::BIGINT, $2::BIGINT)
         )
         ON CONFLICT DO NOTHING`,
        sender,
        u.ID,
    ); err != nil {
        log.Printf("ERROR contactRespond INSERT contacts: %v", err)
        writeError(w, 500, "Gagal menambah kontak")
        return
    }
}
	if _, err = tx.ExecContext(r.Context(), `UPDATE contact_requests SET status=$1 WHERE id=$2`, status, input.RequestID); err != nil {
		writeError(w, 500, "Gagal menyimpan permintaan")
		return
	}
	if err = tx.Commit(); err != nil {
		writeError(w, 500, "Gagal menyimpan permintaan")
		return
	}
	writeJSON(w, 200, map[string]string{"status": status})
}

func (a *App) contactRemove(w http.ResponseWriter, r *http.Request, u *User) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	var input struct {
		UserID int64 `json:"user_id"`
	}
	if decodeJSON(w, r, &input) != nil || input.UserID <= 0 || input.UserID == u.ID {
		writeError(w, 400, "Kontak tidak valid")
		return
	}
	_, err := a.db.ExecContext(r.Context(), `DELETE FROM contacts WHERE user_low=LEAST($1,$2) AND user_high=GREATEST($1,$2)`, u.ID, input.UserID)
	if err != nil {
		writeError(w, 500, "Gagal menghapus kontak")
		return
	}
	writeJSON(w, 200, map[string]string{"message": "Kontak dihapus"})
}

func mediaDir() string {
	if v := os.Getenv("MEDIA_DIR"); v != "" {
		return v
	}
	return "/data/ruangkita-media"
}
func mediaPath(id string) string { return filepath.Join(mediaDir(), id) }

func (a *App) mediaUpload(w http.ResponseWriter, r *http.Request, u *User) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxMediaBytes+(1<<20))
	if err := r.ParseMultipartForm(1 << 20); err != nil {
		writeError(w, 413, "Unggahan terlalu besar atau tidak valid")
		return
	}
	if r.MultipartForm != nil {
		defer r.MultipartForm.RemoveAll()
	}
	receiver, err := strconv.ParseInt(r.FormValue("receiver_id"), 10, 64)
	if err != nil || receiver <= 0 || receiver == u.ID {
		writeError(w, 400, "Penerima tidak valid")
		return
	}
	ok, err := a.areContacts(r, u.ID, receiver)
	if err != nil {
		writeError(w, 500, "Gagal memeriksa kontak")
		return
	}
	if !ok {
		writeError(w, 403, "Penerima belum menjadi kontak")
		return
	}
	file, header, err := r.FormFile("file")
	if err != nil {
		writeError(w, 400, "File wajib diisi")
		return
	}
	defer file.Close()
	if header.Size <= 0 || header.Size > maxMediaBytes {
		writeError(w, 413, "File harus berukuran 1 byte sampai 20 MB")
		return
	}
	buf := make([]byte, 512)
	n, err := io.ReadFull(file, buf)
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		writeError(w, 400, "File tidak valid")
		return
	}
	mime := http.DetectContentType(buf[:n])
	allowed := strings.HasPrefix(mime, "image/") || strings.HasPrefix(mime, "video/") || mime == "application/pdf" || mime == "text/plain" || mime == "application/zip" || mime == "application/octet-stream"
	if !allowed || strings.Contains(mime, "svg") || mime == "text/html" {
		writeError(w, 415, "Jenis file tidak didukung")
		return
	}
	viewOnce := r.FormValue("view_once") == "true"
	if viewOnce && !strings.HasPrefix(mime, "image/") && !strings.HasPrefix(mime, "video/") {
		writeError(w, 400, "Lihat sekali hanya untuk foto atau video")
		return
	}
	if err := os.MkdirAll(mediaDir(), 0700); err != nil {
		log.Printf("media dir: %v", err)
		writeError(w, 500, "Penyimpanan tidak tersedia")
		return
	}
	random := make([]byte, 24)
	if _, err := rand.Read(random); err != nil {
		writeError(w, 500, "Gagal membuat ID file")
		return
	}
	id := hex.EncodeToString(random)
	out, err := os.OpenFile(mediaPath(id), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		writeError(w, 500, "Gagal menyimpan file")
		return
	}
	count, copyErr := io.Copy(out, io.MultiReader(strings.NewReader(string(buf[:n])), io.LimitReader(file, maxMediaBytes+1)))
	closeErr := out.Close()
	if copyErr != nil || closeErr != nil || count > maxMediaBytes {
		os.Remove(mediaPath(id))
		writeError(w, 413, "Gagal menyimpan atau file terlalu besar")
		return
	}
	name := filepath.Base(header.Filename)
	if len(name) > 200 {
		name = name[:200]
	}
	if name == "" {
		name = "file"
	}
	_, err = a.db.ExecContext(r.Context(), `INSERT INTO media_files(id,sender_id,receiver_id,original_name,mime_type,size_bytes,view_once) VALUES($1,$2,$3,$4,$5,$6,$7)`, id, u.ID, receiver, name, mime, count, viewOnce)
	if err != nil {
		os.Remove(mediaPath(id))
		writeError(w, 500, "Gagal menyimpan informasi media")
		return
	}
	writeJSON(w, 201, map[string]any{"id": id, "receiver_id": receiver, "name": name, "mime_type": mime, "size_bytes": count, "view_once": viewOnce, "expires_in": 86400})
}

func (a *App) mediaList(w http.ResponseWriter, r *http.Request, u *User) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	rows, err := a.db.QueryContext(r.Context(), `SELECT id,sender_id,receiver_id,original_name,mime_type,size_bytes,view_once,viewed_at,created_at,expires_at FROM media_files WHERE (sender_id=$1 OR receiver_id=$1) AND expires_at>NOW() AND EXISTS(SELECT 1 FROM contacts WHERE user_low=LEAST(sender_id,receiver_id) AND user_high=GREATEST(sender_id,receiver_id)) ORDER BY created_at DESC LIMIT 300`, u.ID)
	if err != nil {
		writeError(w, 500, "Gagal membaca media")
		return
	}
	defer rows.Close()
	type item struct {
		ID         string     `json:"id"`
		SenderID   int64      `json:"sender_id"`
		ReceiverID int64      `json:"receiver_id"`
		Name       string     `json:"name"`
		MimeType   string     `json:"mime_type"`
		Size       int64      `json:"size_bytes"`
		ViewOnce   bool       `json:"view_once"`
		ViewedAt   *time.Time `json:"viewed_at"`
		CreatedAt  time.Time  `json:"created_at"`
		ExpiresAt  time.Time  `json:"expires_at"`
	}
	result := make([]item, 0)
	for rows.Next() {
		var v item
		if err := rows.Scan(&v.ID, &v.SenderID, &v.ReceiverID, &v.Name, &v.MimeType, &v.Size, &v.ViewOnce, &v.ViewedAt, &v.CreatedAt, &v.ExpiresAt); err != nil {
			writeError(w, 500, "Gagal membaca media")
			return
		}
		result = append(result, v)
	}
	if rows.Err() != nil {
		writeError(w, 500, "Gagal membaca media")
		return
	}
	writeJSON(w, 200, result)
}

func (a *App) mediaGet(w http.ResponseWriter, r *http.Request, u *User) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/media/file/")
	if len(id) != 48 {
		writeError(w, 404, "Media tidak ditemukan")
		return
	}
	if _, err := hex.DecodeString(id); err != nil {
		writeError(w, 404, "Media tidak ditemukan")
		return
	}
	var sender, receiver int64
	var name, mime string
	var once bool
	var viewed sql.NullTime
	err := a.db.QueryRowContext(r.Context(), `SELECT sender_id,receiver_id,original_name,mime_type,view_once,viewed_at FROM media_files WHERE id=$1 AND expires_at>NOW()`, id).Scan(&sender, &receiver, &name, &mime, &once, &viewed)
	if errors.Is(err, sql.ErrNoRows) {
		writeError(w, 404, "Media kedaluwarsa atau tidak ditemukan")
		return
	}
	if err != nil {
		writeError(w, 500, "Gagal membaca media")
		return
	}
	adminDownload := u.IsAdmin && r.URL.Query().Get("download") == "1"
	if !adminDownload && u.ID != sender && u.ID != receiver {
		writeError(w, 403, "Tidak berhak mengakses media")
		return
	}
	if !adminDownload {
		ok, err := a.areContacts(r, sender, receiver)
		if err != nil || !ok {
			writeError(w, 403, "Bukan kontak aktif")
			return
		}
	}
	f, err := os.Open(mediaPath(id))
	if err != nil {
		writeError(w, 404, "File tidak tersedia")
		return
	}
	defer f.Close()
	stat, err := f.Stat()
	if err != nil {
		writeError(w, 404, "File tidak tersedia")
		return
	}
	if once && !adminDownload {
		if u.ID == sender {
			writeError(w, 403, "Media lihat sekali hanya untuk penerima")
			return
		}
		res, err := a.db.ExecContext(r.Context(), `UPDATE media_files SET viewed_at=NOW() WHERE id=$1 AND viewed_at IS NULL AND expires_at>NOW()`, id)
		if err != nil {
			writeError(w, 500, "Gagal membuka media")
			return
		}
		n, _ := res.RowsAffected()
		if n == 0 {
			writeError(w, 410, "Media sudah pernah dilihat")
			return
		}
	}
	w.Header().Set("Content-Type", mime)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store, private")
	w.Header().Set("Content-Security-Policy", "sandbox")
	disposition := "attachment"
	if !adminDownload && (strings.HasPrefix(mime, "image/") || strings.HasPrefix(mime, "video/")) {
		disposition = "inline"
	}
	w.Header().Set("Content-Disposition", fmt.Sprintf("%s; filename=%q", disposition, name))
	w.Header().Set("Content-Length", strconv.FormatInt(stat.Size(), 10))
	io.Copy(w, f)
}

func (a *App) adminUsers(w http.ResponseWriter, r *http.Request, u *User) {
	if !u.IsAdmin {
		writeError(w, 403, "Hanya admin")
		return
	}
	a.usersAll(w, r)
}
func (a *App) usersAll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	rows, err := a.db.QueryContext(r.Context(), `SELECT id,username,display_name,is_admin FROM users WHERE is_active=TRUE ORDER BY username`)
	if err != nil {
		writeError(w, 500, "Gagal membaca anggota")
		return
	}
	defer rows.Close()
	result := make([]User, 0)
	for rows.Next() {
		var v User
		if rows.Scan(&v.ID, &v.Username, &v.DisplayName, &v.IsAdmin) != nil {
			writeError(w, 500, "Gagal membaca anggota")
			return
		}
		result = append(result, v)
	}
	if rows.Err() != nil {
		writeError(w, 500, "Gagal membaca anggota")
		return
	}
	writeJSON(w, 200, result)
}

func (a *App) cleanupMedia() {
	rows, err := a.db.Query(`SELECT id FROM media_files WHERE expires_at<=NOW() LIMIT 500`)
	if err != nil {
		log.Printf("cleanup query: %v", err)
		return
	}
	var ids []string
	for rows.Next() {
		var id string
		if rows.Scan(&id) == nil {
			ids = append(ids, id)
		}
	}
	rows.Close()
	for _, id := range ids {
		if err := os.Remove(mediaPath(id)); err != nil && !os.IsNotExist(err) {
			log.Printf("cleanup file: %v", err)
			continue
		}
		if _, err := a.db.Exec(`DELETE FROM media_files WHERE id=$1 AND expires_at<=NOW()`, id); err != nil {
			log.Printf("cleanup db: %v", err)
		}
	}
}
func (a *App) startMediaCleanup() {
	go func() {
		a.cleanupMedia()
		ticker := time.NewTicker(10 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			a.cleanupMedia()
		}
	}()
}
