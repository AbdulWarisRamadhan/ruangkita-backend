package main

// Isolated V4 additions. All endpoints authenticate using the existing bearer-session middleware.
import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

func (a *App) deleteMessageV4(w http.ResponseWriter, r *http.Request, u *User) {
	if r.Method != http.MethodDelete {
		methodNotAllowed(w)
		return
	}
	id, err := strconv.ParseInt(strings.TrimPrefix(r.URL.Path, "/v4/messages/"), 10, 64)
	if err != nil || id <= 0 {
		writeError(w, 400, "ID pesan tidak valid")
		return
	}
	var sender, receiver string
	err = a.db.QueryRowContext(r.Context(), `SELECT sender_id,receiver_id FROM messages WHERE id=$1`, id).Scan(&sender, &receiver)
	if errors.Is(err, sql.ErrNoRows) {
		writeError(w, 404, "Pesan tidak ditemukan")
		return
	}
	if err != nil {
		writeError(w, 500, "Gagal membaca pesan")
		return
	}
	myID := strconv.FormatInt(u.ID, 10)
	if myID != sender && myID != receiver {
		writeError(w, 403, "Tidak diizinkan")
		return
	}
	peer := sender
	if sender == myID {
		peer = receiver
	}
	peerID, _ := strconv.ParseInt(peer, 10, 64)
	ok, err := a.areContacts(r, u.ID, peerID)
	if err != nil || !ok {
		writeError(w, 403, "Bukan kontak aktif")
		return
	}
	scope := r.URL.Query().Get("scope")
	switch scope {
	case "me":
		_, err = a.db.ExecContext(r.Context(), `INSERT INTO hidden_messages(message_id,user_id) VALUES($1,$2) ON CONFLICT DO NOTHING`, id, u.ID)
	case "everyone":
		if myID != sender {
			writeError(w, 403, "Hanya pengirim yang boleh menghapus untuk semua")
			return
		}
		_, err = a.db.ExecContext(r.Context(), `UPDATE messages SET deleted_for_everyone=TRUE,deleted_at=NOW(),content='' WHERE id=$1 AND sender_id=$2`, id, myID)
	default:
		writeError(w, 400, "Scope harus me atau everyone")
		return
	}
	if err != nil {
		writeError(w, 500, "Gagal menghapus pesan")
		return
	}
	writeJSON(w, 200, map[string]string{"status": "ok"})
}
func (a *App) clearChatV4(w http.ResponseWriter, r *http.Request, u *User) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	var input struct {
		PeerID int64 `json:"peer_id"`
	}
	if decodeJSON(w, r, &input) != nil || input.PeerID <= 0 || input.PeerID == u.ID {
		writeError(w, 400, "Kontak tidak valid")
		return
	}
	ok, err := a.areContacts(r, u.ID, input.PeerID)
	if err != nil || !ok {
		writeError(w, 403, "Bukan kontak aktif")
		return
	}
	_, err = a.db.ExecContext(r.Context(), `INSERT INTO conversation_clears(user_id,peer_id,cleared_at) VALUES($1,$2,NOW()) ON CONFLICT(user_id,peer_id) DO UPDATE SET cleared_at=NOW()`, u.ID, input.PeerID)
	if err != nil {
		writeError(w, 500, "Gagal membersihkan chat")
		return
	}
	writeJSON(w, 200, map[string]string{"status": "ok"})
}
func (a *App) readChatV4(w http.ResponseWriter, r *http.Request, u *User) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	var input struct {
		PeerID int64 `json:"peer_id"`
	}
	if decodeJSON(w, r, &input) != nil || input.PeerID <= 0 || input.PeerID == u.ID {
		writeError(w, 400, "Kontak tidak valid")
		return
	}
	ok, err := a.areContacts(r, u.ID, input.PeerID)
	if err != nil || !ok {
		writeError(w, 403, "Bukan kontak aktif")
		return
	}
	_, err = a.db.ExecContext(r.Context(), `INSERT INTO message_reads(message_id,reader_id)
 SELECT id,$1 FROM messages WHERE sender_id=$2 AND receiver_id=$3 AND deleted_for_everyone=FALSE
 ON CONFLICT DO NOTHING`, u.ID, strconv.FormatInt(input.PeerID, 10), strconv.FormatInt(u.ID, 10))
	if err != nil {
		writeError(w, 500, "Gagal menandai pesan dibaca")
		return
	}
	writeJSON(w, 200, map[string]string{"status": "ok"})
}
func (a *App) presenceV4(w http.ResponseWriter, r *http.Request, u *User) {
	switch r.Method {
	case http.MethodPost:
		_, err := a.db.ExecContext(r.Context(), `INSERT INTO user_presence(user_id,last_seen) VALUES($1,NOW()) ON CONFLICT(user_id) DO UPDATE SET last_seen=NOW()`, u.ID)
		if err != nil {
			writeError(w, 500, "Gagal menyimpan status")
			return
		}
		writeJSON(w, 200, map[string]string{"status": "ok"})
	case http.MethodGet:
		peer, err := strconv.ParseInt(r.URL.Query().Get("peer_id"), 10, 64)
		if err != nil || peer <= 0 || peer == u.ID {
			writeError(w, 400, "ID kontak tidak valid")
			return
		}
		ok, err := a.areContacts(r, u.ID, peer)
		if err != nil || !ok {
			writeError(w, 403, "Bukan kontak aktif")
			return
		}
		var last sql.NullTime
		err = a.db.QueryRowContext(r.Context(), `SELECT last_seen FROM user_presence WHERE user_id=$1`, peer).Scan(&last)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			writeError(w, 500, "Gagal membaca status")
			return
		}
		online := last.Valid && time.Since(last.Time) < 45*time.Second
		writeJSON(w, 200, map[string]any{"online": online, "last_seen": last.Time, "has_last_seen": last.Valid})
	default:
		methodNotAllowed(w)
	}
}
func (a *App) invitesV4(w http.ResponseWriter, r *http.Request, u *User) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		writeError(w, 500, "Gagal membuat undangan")
		return
	}
	secret := hex.EncodeToString(b[:])
	hash := sha256.Sum256([]byte(secret))
	_, err := a.db.ExecContext(r.Context(), `INSERT INTO contact_invites(token_hash,owner_id,expires_at) VALUES($1,$2,NOW()+INTERVAL '7 days')`, hex.EncodeToString(hash[:]), u.ID)
	if err != nil {
		writeError(w, 500, "Gagal menyimpan undangan")
		return
	}
	writeJSON(w, 201, map[string]any{"token": secret, "expires_in": 604800})
}
func (a *App) acceptInviteV4(w http.ResponseWriter, r *http.Request, u *User) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	var input struct {
		Token string `json:"token"`
	}
	if decodeJSON(w, r, &input) != nil || len(input.Token) != 64 {
		writeError(w, 400, "Tautan undangan tidak valid")
		return
	}
	if _, err := hex.DecodeString(input.Token); err != nil {
		writeError(w, 400, "Tautan undangan tidak valid")
		return
	}
	hashed := sha256.Sum256([]byte(input.Token))
	tx, err := a.db.BeginTx(r.Context(), nil)
	if err != nil {
		writeError(w, 500, "Gagal memproses undangan")
		return
	}
	defer tx.Rollback()
	var owner int64
	err = tx.QueryRowContext(r.Context(), `SELECT owner_id FROM contact_invites WHERE token_hash=$1 AND used_by IS NULL AND expires_at>NOW() FOR UPDATE`, hex.EncodeToString(hashed[:])).Scan(&owner)
	if errors.Is(err, sql.ErrNoRows) {
		writeError(w, 404, "Undangan kedaluwarsa atau telah dipakai")
		return
	}
	if err != nil {
		writeError(w, 500, "Gagal memeriksa undangan")
		return
	}
	if owner == u.ID {
		writeError(w, 400, "Tidak bisa mengundang diri sendiri")
		return
	}
	var already bool
	err = tx.QueryRowContext(r.Context(), `SELECT EXISTS(SELECT 1 FROM contacts WHERE user_low=LEAST($1,$2) AND user_high=GREATEST($1,$2))`, owner, u.ID).Scan(&already)
	if err != nil {
		writeError(w, 500, "Gagal memeriksa kontak")
		return
	}
	if !already {
		_, err = tx.ExecContext(r.Context(), `INSERT INTO contact_requests(sender_id,receiver_id,status) VALUES($1,$2,'pending') ON CONFLICT DO NOTHING`, u.ID, owner)
		if err != nil { // Existing pending pair can trigger unique-index violation rather than ON CONFLICT DO NOTHING in some schemas.
			var pending bool
			_ = tx.QueryRowContext(r.Context(), `SELECT EXISTS(SELECT 1 FROM contact_requests WHERE status='pending' AND LEAST(sender_id,receiver_id)=LEAST($1,$2) AND GREATEST(sender_id,receiver_id)=GREATEST($1,$2))`, u.ID, owner).Scan(&pending)
			if !pending {
				writeError(w, 500, "Gagal mengirim permintaan kontak")
				return
			}
		}
	}
	_, err = tx.ExecContext(r.Context(), `UPDATE contact_invites SET used_by=$2 WHERE token_hash=$1`, hex.EncodeToString(hashed[:]), u.ID)
	if err != nil {
		writeError(w, 500, "Gagal menyimpan undangan")
		return
	}
	if err = tx.Commit(); err != nil {
		writeError(w, 500, "Gagal menyimpan undangan")
		return
	}
	writeJSON(w, 200, map[string]string{"status": "request_sent"})
}
func (a *App) stickersV4(w http.ResponseWriter, r *http.Request, u *User) {
	switch r.Method {
	case http.MethodGet:
		rows, err := a.db.QueryContext(r.Context(), `SELECT s.id,s.media_id,m.original_name FROM sticker_library s JOIN media_files m ON m.id=s.media_id WHERE s.owner_id=$1 ORDER BY s.id DESC LIMIT 100`, u.ID)
		if err != nil {
			writeError(w, 500, "Gagal mengambil stiker")
			return
		}
		defer rows.Close()
		type Sticker struct {
			ID      int64  `json:"id"`
			MediaID string `json:"media_id"`
			Name    string `json:"name"`
		}
		items := make([]Sticker, 0)
		for rows.Next() {
			var s Sticker
			if rows.Scan(&s.ID, &s.MediaID, &s.Name) != nil {
				writeError(w, 500, "Gagal membaca stiker")
				return
			}
			items = append(items, s)
		}
		if rows.Err() != nil {
			writeError(w, 500, "Gagal membaca stiker")
			return
		}
		writeJSON(w, 200, items)
	case http.MethodDelete:
		var input struct {
			ID int64 `json:"id"`
		}
		if decodeJSON(w, r, &input) != nil || input.ID <= 0 {
			writeError(w, 400, "Stiker tidak valid")
			return
		}
		tx, err := a.db.BeginTx(r.Context(), nil)
		if err != nil {
			writeError(w, 500, "Gagal memulai penghapusan stiker")
			return
		}
		defer tx.Rollback()
		var mediaID string
		err = tx.QueryRowContext(r.Context(), `DELETE FROM sticker_library WHERE id=$1 AND owner_id=$2 RETURNING media_id`, input.ID, u.ID).Scan(&mediaID)
		if errors.Is(err, sql.ErrNoRows) {
			writeError(w, 404, "Stiker tidak ditemukan")
			return
		}
		if err != nil {
			writeError(w, 500, "Gagal menghapus stiker")
			return
		}
		if _, err = tx.ExecContext(r.Context(), `DELETE FROM media_files WHERE id=$1 AND sender_id=$2 AND receiver_id=$2 AND kind='sticker'`, mediaID, u.ID); err != nil {
			writeError(w, 500, "Gagal menghapus file stiker")
			return
		}
		if err = tx.Commit(); err != nil {
			writeError(w, 500, "Gagal menyimpan penghapusan stiker")
			return
		}
		// Pesan stiker terkirim memiliki salinan file yang terpisah.
		_ = os.Remove(mediaPath(mediaID))
		writeJSON(w, 200, map[string]string{"status": "ok"})
	default:
		methodNotAllowed(w)
	}
}
func (a *App) sendStickerV4(w http.ResponseWriter, r *http.Request, u *User) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	var input struct {
		ID         int64 `json:"id"`
		ReceiverID int64 `json:"receiver_id"`
	}
	if decodeJSON(w, r, &input) != nil || input.ID <= 0 || input.ReceiverID <= 0 || input.ReceiverID == u.ID {
		writeError(w, 400, "Stiker atau penerima tidak valid")
		return
	}
	ok, err := a.areContacts(r, u.ID, input.ReceiverID)
	if err != nil || !ok {
		writeError(w, 403, "Bukan kontak aktif")
		return
	}
	var src string
	var name, mime string
	var sz int64
	err = a.db.QueryRowContext(r.Context(), `SELECT m.id,m.original_name,m.mime_type,m.size_bytes FROM sticker_library s JOIN media_files m ON m.id=s.media_id WHERE s.id=$1 AND s.owner_id=$2`, input.ID, u.ID).Scan(&src, &name, &mime, &sz)
	if errors.Is(err, sql.ErrNoRows) {
		writeError(w, 404, "Stiker tidak ada di koleksi")
		return
	}
	if err != nil {
		writeError(w, 500, "Gagal membaca stiker")
		return
	}
	b := make([]byte, 24)
	if _, err = rand.Read(b); err != nil {
		writeError(w, 500, "Gagal mengirim stiker")
		return
	}
	id := hex.EncodeToString(b)
	in, err := os.Open(mediaPath(src))
	if err != nil {
		writeError(w, 404, "File stiker tidak tersedia")
		return
	}
	defer in.Close()
	out, err := os.OpenFile(mediaPath(id), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		writeError(w, 500, "Gagal menyimpan stiker")
		return
	}
	_, err = io.Copy(out, in)
	closeErr := out.Close()
	if err != nil || closeErr != nil {
		os.Remove(mediaPath(id))
		writeError(w, 500, "Gagal menyalin stiker")
		return
	}
	_, err = a.db.ExecContext(r.Context(), `INSERT INTO media_files(id,sender_id,receiver_id,original_name,mime_type,size_bytes,view_once,kind,expires_at) VALUES($1,$2,$3,$4,$5,$6,FALSE,'sticker',NOW()+INTERVAL '100 years')`, id, u.ID, input.ReceiverID, name, mime, sz)
	if err != nil {
		os.Remove(mediaPath(id))
		writeError(w, 500, "Gagal menyimpan stiker")
		return
	}
	writeJSON(w, 201, map[string]string{"id": id, "kind": "sticker"})
}
func (a *App) adminMediaV4(w http.ResponseWriter, r *http.Request, u *User) {
	if !u.IsAdmin {
		writeError(w, 403, "Hanya administrator")
		return
	}
	switch r.Method {
	case http.MethodGet:
		rows, err := a.db.QueryContext(r.Context(), `SELECT id,original_name,mime_type,kind,size_bytes,created_at FROM media_files ORDER BY created_at DESC LIMIT 150`)
		if err != nil {
			writeError(w, 500, "Gagal membaca media")
			return
		}
		defer rows.Close()
		type Item struct {
			ID        string    `json:"id"`
			Name      string    `json:"name"`
			MimeType  string    `json:"mime_type"`
			Kind      string    `json:"kind"`
			Size      int64     `json:"size_bytes"`
			CreatedAt time.Time `json:"created_at"`
		}
		items := make([]Item, 0)
		for rows.Next() {
			var v Item
			if rows.Scan(&v.ID, &v.Name, &v.MimeType, &v.Kind, &v.Size, &v.CreatedAt) != nil {
				writeError(w, 500, "Gagal membaca media")
				return
			}
			items = append(items, v)
		}
		if rows.Err() != nil {
			writeError(w, 500, "Gagal membaca media")
			return
		}
		writeJSON(w, 200, items)
	case http.MethodDelete:
		var input struct {
			ID string `json:"id"`
		}
		if decodeJSON(w, r, &input) != nil || len(input.ID) != 48 {
			writeError(w, 400, "ID tidak valid")
			return
		}
		if _, err := hex.DecodeString(input.ID); err != nil {
			writeError(w, 400, "ID tidak valid")
			return
		}
		result, err := a.db.ExecContext(r.Context(), `DELETE FROM media_files WHERE id=$1`, input.ID)
		if err != nil {
			writeError(w, 500, "Gagal menghapus data media")
			return
		}
		count, _ := result.RowsAffected()
		if count == 0 {
			writeError(w, 404, "Media tidak ditemukan")
			return
		}
		if err := os.Remove(mediaPath(input.ID)); err != nil && !os.IsNotExist(err) {
			fmt.Printf("peringatan: file media belum terhapus: %v\n", err)
		}
		writeJSON(w, 200, map[string]string{"status": "ok"})
	default:
		methodNotAllowed(w)
	}
}

// Existing frontend admin contacts route, present in the UI but missing in uploaded backend snapshot.
func (a *App) adminContacts(w http.ResponseWriter, r *http.Request, u *User) {
	if !u.IsAdmin {
		writeError(w, 403, "Hanya administrator")
		return
	}
	switch r.Method {
	case http.MethodGet:
		userID, err := strconv.ParseInt(r.URL.Query().Get("user_id"), 10, 64)
		if err != nil || userID <= 0 {
			writeError(w, 400, "ID pengguna tidak valid")
			return
		}
		rows, err := a.db.QueryContext(r.Context(), `SELECT usr.id,usr.username,usr.display_name,usr.is_admin
    FROM contacts c JOIN users usr ON usr.id=CASE WHEN c.user_low=$1 THEN c.user_high ELSE c.user_low END
    WHERE (c.user_low=$1 OR c.user_high=$1) AND usr.is_active=TRUE ORDER BY usr.display_name`, userID)
		if err != nil {
			writeError(w, 500, "Gagal membaca daftar kontak")
			return
		}
		defer rows.Close()
		items := make([]User, 0)
		for rows.Next() {
			var v User
			if rows.Scan(&v.ID, &v.Username, &v.DisplayName, &v.IsAdmin) != nil {
				writeError(w, 500, "Gagal membaca kontak")
				return
			}
			items = append(items, v)
		}
		if rows.Err() != nil {
			writeError(w, 500, "Gagal membaca kontak")
			return
		}
		writeJSON(w, 200, items)
	case http.MethodPost:
		var input struct {
			UserID    int64 `json:"user_id"`
			ContactID int64 `json:"contact_id"`
		}
		if decodeJSON(w, r, &input) != nil || input.UserID <= 0 || input.ContactID <= 0 || input.UserID == input.ContactID {
			writeError(w, 400, "Kontak tidak valid")
			return
		}
		_, err := a.db.ExecContext(r.Context(), `DELETE FROM contacts WHERE user_low=LEAST($1,$2) AND user_high=GREATEST($1,$2)`, input.UserID, input.ContactID)
		if err != nil {
			writeError(w, 500, "Gagal menghapus hubungan kontak")
			return
		}
		writeJSON(w, 200, map[string]string{"status": "ok"})
	default:
		methodNotAllowed(w)
	}
}

func (a *App) deleteMediaV4(w http.ResponseWriter, r *http.Request, u *User) {
	if r.Method != http.MethodDelete {
		methodNotAllowed(w)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/v4/media/")
	if len(id) != 48 {
		writeError(w, 400, "ID media tidak valid")
		return
	}
	if _, err := hex.DecodeString(id); err != nil {
		writeError(w, 400, "ID media tidak valid")
		return
	}
	var sender, receiver int64
	err := a.db.QueryRowContext(r.Context(), `SELECT sender_id,receiver_id FROM media_files WHERE id=$1 AND sender_id<>receiver_id`, id).Scan(&sender, &receiver)
	if errors.Is(err, sql.ErrNoRows) {
		writeError(w, 404, "Media tidak ditemukan")
		return
	}
	if err != nil {
		writeError(w, 500, "Gagal membaca media")
		return
	}
	if u.ID != sender && u.ID != receiver {
		writeError(w, 403, "Tidak berhak menghapus media")
		return
	}
	ok, err := a.areContacts(r, sender, receiver)
	if err != nil || !ok {
		writeError(w, 403, "Bukan kontak aktif")
		return
	}
	scope := r.URL.Query().Get("scope")
	switch scope {
	case "me":
		_, err = a.db.ExecContext(r.Context(), `INSERT INTO hidden_media(media_id,user_id) VALUES($1,$2) ON CONFLICT DO NOTHING`, id, u.ID)
	case "everyone":
		if sender != u.ID {
			writeError(w, 403, "Hanya pengirim yang boleh menghapus media untuk semua")
			return
		}
		_, err = a.db.ExecContext(r.Context(), `UPDATE media_files SET deleted_for_everyone=TRUE WHERE id=$1 AND sender_id=$2`, id, u.ID)
	default:
		writeError(w, 400, "Scope harus me atau everyone")
		return
	}
	if err != nil {
		writeError(w, 500, "Gagal menghapus media")
		return
	}
	writeJSON(w, 200, map[string]string{"status": "ok"})
}
