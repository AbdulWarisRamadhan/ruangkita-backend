package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5/pgconn"
	_ "github.com/jackc/pgx/v5/stdlib"
	"golang.org/x/crypto/bcrypt"
)

const (
	sessionLifetime = 7 * 24 * time.Hour
	maxRequestBody  = 64 << 10
	loginWindow     = 15 * time.Minute
	maxLoginFails   = 10
	maxLoginEntries = 5000
)

var errInvalidSession = errors.New("sesi tidak valid")

type contextKey string

const userKey contextKey = "authenticated_user"

type User struct {
	ID          int64  `json:"id"`
	Username    string `json:"username"`
	DisplayName string `json:"display_name"`
	IsAdmin     bool   `json:"is_admin"`
}

type Message struct {
	ID         int64     `json:"id"`
	SenderID   string    `json:"sender_id"`
	ReceiverID string    `json:"receiver_id"`
	Content    string    `json:"content"`
	CreatedAt  time.Time `json:"created_at"`
}

type App struct {
	db        *sql.DB
	dummyHash []byte
}

type attemptRecord struct {
	count      int
	windowEnds time.Time
}

var loginLimiter = struct {
	sync.Mutex
	records map[string]attemptRecord
}{
	records: make(map[string]attemptRecord),
}

func blockedLogin(ip string) bool {
	loginLimiter.Lock()
	defer loginLimiter.Unlock()

	now := time.Now()
	record, exists := loginLimiter.records[ip]
	if !exists {
		return len(loginLimiter.records) >= maxLoginEntries
	}

	if !now.Before(record.windowEnds) {
		delete(loginLimiter.records, ip)
		return false
	}

	return record.count >= maxLoginFails
}

func failedLogin(ip string) {
	loginLimiter.Lock()
	defer loginLimiter.Unlock()

	now := time.Now()

	// Bersihkan catatan kedaluwarsa agar map tetap terbatas.
	if len(loginLimiter.records) >= maxLoginEntries {
		for key, record := range loginLimiter.records {
			if !now.Before(record.windowEnds) {
				delete(loginLimiter.records, key)
			}
		}
	}

	record, exists := loginLimiter.records[ip]
	if !exists || !now.Before(record.windowEnds) {
		record = attemptRecord{
			count:      0,
			windowEnds: now.Add(loginWindow),
		}
	}

	if len(loginLimiter.records) >= maxLoginEntries && !exists {
		return
	}
	record.count++
	loginLimiter.records[ip] = record
}

func clearLoginFailures(ip string) {
	loginLimiter.Lock()
	defer loginLimiter.Unlock()
	delete(loginLimiter.records, ip)
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

func decodeJSON(w http.ResponseWriter, r *http.Request, target any) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)

	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(target); err != nil {
		return err
	}

	var extra any
	err := decoder.Decode(&extra)
	if !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("hanya satu objek JSON yang diizinkan")
		}
		return err
	}

	return nil
}

func validText(value string, min, max int) bool {
	length := utf8.RuneCountInString(strings.TrimSpace(value))
	return length >= min && length <= max
}

func methodNotAllowed(w http.ResponseWriter) {
	writeError(w, http.StatusMethodNotAllowed, "Metode HTTP tidak diizinkan")
}

func databaseDSN() (string, error) {
	host := strings.TrimSpace(os.Getenv("DB_HOST"))
	port := strings.TrimSpace(os.Getenv("DB_PORT"))
	name := strings.TrimSpace(os.Getenv("DB_NAME"))
	user := os.Getenv("DB_USER")
	password := os.Getenv("DB_PASSWORD")

	if host == "" || port == "" || name == "" ||
		user == "" || password == "" {
		return "", errors.New(
			"DB_HOST, DB_PORT, DB_NAME, DB_USER, dan DB_PASSWORD wajib diatur",
		)
	}

	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return "", errors.New("DB_PORT harus berupa nomor port 1-65535")
	}

	u := url.URL{
		Scheme: "postgres",
		User:   url.UserPassword(user, password),
		Host:   net.JoinHostPort(host, port),
		Path:   name,
	}

	query := u.Query()

	sslMode := strings.TrimSpace(os.Getenv("DB_SSLMODE"))
	if sslMode == "" {
		sslMode = "disable"
	}
	switch sslMode {
	case "disable", "require", "verify-ca", "verify-full":
	default:
		return "", errors.New("DB_SSLMODE tidak valid")
	}

	query.Set("sslmode", sslMode)
	u.RawQuery = query.Encode()

	return u.String(), nil
}

func generateToken() (string, error) {
	data := make([]byte, 32)
	if _, err := rand.Read(data); err != nil {
		return "", err
	}
	return hex.EncodeToString(data), nil
}

func tokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func bearerToken(r *http.Request) (string, error) {
	header := r.Header.Get("Authorization")
	if !strings.HasPrefix(header, "Bearer ") {
		return "", errInvalidSession
	}

	token := strings.TrimSpace(strings.TrimPrefix(header, "Bearer "))
	if len(token) != 64 {
		return "", errInvalidSession
	}

	if _, err := hex.DecodeString(token); err != nil {
		return "", errInvalidSession
	}

	return token, nil
}

// Buat admin awal hanya ketika tabel users benar-benar kosong.
// BOOTSTRAP_ADMIN_PASSWORD tidak pernah disimpan di source code.
func bootstrapAdmin(db *sql.DB) error {
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("memulai bootstrap admin: %w", err)
	}
	defer tx.Rollback()

	// Mencegah dua instance backend melakukan bootstrap bersamaan.
	var lockResult any
	if err := tx.QueryRow(`SELECT pg_advisory_xact_lock(736219401)`).Scan(&lockResult); err != nil {
		return fmt.Errorf("mengunci bootstrap admin: %w", err)
	}

	var count int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&count); err != nil {
		return fmt.Errorf("memeriksa tabel users: %w", err)
	}

	if count > 0 {
		log.Println("Bootstrap admin dilewati: akun pengguna sudah tersedia")
		return tx.Commit()
	}

	password := os.Getenv("BOOTSTRAP_ADMIN_PASSWORD")
	if len(password) < 12 || len(password) > 72 || !utf8.ValidString(password) {
		return errors.New(
			"tabel users kosong: BOOTSTRAP_ADMIN_PASSWORD wajib diatur, " +
				"minimal 12 dan maksimal 72 byte; gunakan setidaknya 16 karakter",
		)
	}

	hash, err := bcrypt.GenerateFromPassword(
		[]byte(password),
		bcrypt.DefaultCost,
	)
	if err != nil {
		return fmt.Errorf("membuat hash admin: %w", err)
	}

	_, err = tx.Exec(`
		INSERT INTO users
			(username, password_hash, display_name, is_admin, is_active)
		VALUES ($1, $2, $3, TRUE, TRUE)
	`, "alin", string(hash), "Alin")
	if err != nil {
		return fmt.Errorf("menyimpan admin awal: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("menyelesaikan bootstrap admin: %w", err)
	}

	log.Println("Akun admin awal berhasil dibuat")
	return nil
}

func (a *App) authenticate(r *http.Request) (*User, error) {
	token, err := bearerToken(r)
	if err != nil {
		return nil, err
	}

	var user User
	err = a.db.QueryRowContext(r.Context(), `
		SELECT u.id, u.username, u.display_name, u.is_admin
		FROM sessions s
		JOIN users u ON u.id = s.user_id
		WHERE s.token_hash = $1
		  AND s.expires_at > NOW()
		  AND u.is_active = TRUE
	`, tokenHash(token)).Scan(
		&user.ID,
		&user.Username,
		&user.DisplayName,
		&user.IsAdmin,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errInvalidSession
		}
		return nil, err
	}

	return &user, nil
}

type authenticatedHandler func(
	http.ResponseWriter,
	*http.Request,
	*User,
)

func (a *App) requireAuth(next authenticatedHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, err := a.authenticate(r)
		if err != nil {
			if errors.Is(err, errInvalidSession) {
				writeError(
					w,
					http.StatusUnauthorized,
					"Sesi tidak valid atau sudah berakhir",
				)
				return
			}

			log.Printf("Kesalahan autentikasi: %v", err)
			writeError(
				w,
				http.StatusInternalServerError,
				"Gagal memeriksa sesi",
			)
			return
		}

		next(w, r, user)
	}
}

func (a *App) health(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	if err := a.db.PingContext(ctx); err != nil {
		writeError(
			w,
			http.StatusServiceUnavailable,
			"Database tidak tersedia",
		)
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (a *App) login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}

	ip := clientIP(r)
	if blockedLogin(ip) {
		writeError(
			w,
			http.StatusTooManyRequests,
			"Terlalu banyak percobaan login. Coba lagi setelah 15 menit.",
		)
		return
	}

	var input struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := decodeJSON(w, r, &input); err != nil {
		writeError(w, http.StatusBadRequest, "Format JSON tidak valid")
		return
	}

	input.Username = strings.TrimSpace(input.Username)
	if !validText(input.Username, 1, 50) ||
		len(input.Username) > 50 ||
		len(input.Password) == 0 || len(input.Password) > 72 || !utf8.ValidString(input.Password) {
		failedLogin(ip)
		writeError(
			w,
			http.StatusUnauthorized,
			"Username atau kata sandi salah",
		)
		return
	}

	var user User
	var passwordHash string

	err := a.db.QueryRowContext(r.Context(), `
		SELECT id, username, display_name, is_admin, password_hash
		FROM users
		WHERE username = $1 AND is_active = TRUE
	`, input.Username).Scan(
		&user.ID,
		&user.Username,
		&user.DisplayName,
		&user.IsAdmin,
		&passwordHash,
	)

	if errors.Is(err, sql.ErrNoRows) {
		// Perbandingan dummy mengurangi perbedaan waktu respons
		// untuk username yang tidak ditemukan.
		_ = bcrypt.CompareHashAndPassword(
			a.dummyHash,
			[]byte(input.Password),
		)
		failedLogin(ip)
		writeError(
			w,
			http.StatusUnauthorized,
			"Username atau kata sandi salah",
		)
		return
	}

	if err != nil {
		log.Printf("Kesalahan query login: %v", err)
		writeError(
			w,
			http.StatusInternalServerError,
			"Gagal memproses login",
		)
		return
	}

	if bcrypt.CompareHashAndPassword(
		[]byte(passwordHash),
		[]byte(input.Password),
	) != nil {
		failedLogin(ip)
		writeError(
			w,
			http.StatusUnauthorized,
			"Username atau kata sandi salah",
		)
		return
	}

	token, err := generateToken()
	if err != nil {
		log.Printf("Gagal membuat token sesi: %v", err)
		writeError(
			w,
			http.StatusInternalServerError,
			"Gagal membuat sesi",
		)
		return
	}

	_, err = a.db.ExecContext(r.Context(), `
		INSERT INTO sessions (user_id, token_hash, expires_at)
		VALUES ($1, $2, $3)
	`, user.ID, tokenHash(token), time.Now().Add(sessionLifetime))
	if err != nil {
		log.Printf("Gagal menyimpan sesi: %v", err)
		writeError(
			w,
			http.StatusInternalServerError,
			"Gagal menyimpan sesi",
		)
		return
	}

	clearLoginFailures(ip)

	writeJSON(w, http.StatusOK, map[string]any{
		"token":      token,
		"expires_in": int(sessionLifetime.Seconds()),
		"user":       user,
	})
}

func (a *App) me(
	w http.ResponseWriter,
	r *http.Request,
	user *User,
) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}

	writeJSON(w, http.StatusOK, user)
}

func (a *App) logout(
	w http.ResponseWriter,
	r *http.Request,
	user *User,
) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}

	token, err := bearerToken(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "Sesi tidak valid")
		return
	}

	_, err = a.db.ExecContext(r.Context(), `
		DELETE FROM sessions
		WHERE token_hash = $1
	`, tokenHash(token))
	if err != nil {
		log.Printf("Gagal logout: %v", err)
		writeError(
			w,
			http.StatusInternalServerError,
			"Gagal mengakhiri sesi",
		)
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"message": "Berhasil logout",
	})
}

func (a *App) register(
	w http.ResponseWriter,
	r *http.Request,
	admin *User,
) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}

	if !admin.IsAdmin {
		writeError(
			w,
			http.StatusForbidden,
			"Hanya admin yang dapat membuat akun",
		)
		return
	}

	var input struct {
		Username    string `json:"username"`
		Password    string `json:"password"`
		DisplayName string `json:"display_name"`
	}

	if err := decodeJSON(w, r, &input); err != nil {
		writeError(w, http.StatusBadRequest, "Format JSON tidak valid")
		return
	}

	input.Username = strings.TrimSpace(input.Username)
	input.DisplayName = strings.TrimSpace(input.DisplayName)

	if !validText(input.Username, 3, 50) ||
		len(input.Username) > 50 ||
		!validText(input.DisplayName, 1, 100) ||
		len(input.DisplayName) > 400 ||
		len(input.Password) < 12 || len(input.Password) > 72 || !utf8.ValidString(input.Password) {
		writeError(
			w,
			http.StatusBadRequest,
			"Username harus 3-50 karakter, nama 1-100 karakter, "+
				"dan kata sandi 12-72 byte",
		)
		return
	}

	hash, err := bcrypt.GenerateFromPassword(
		[]byte(input.Password),
		bcrypt.DefaultCost,
	)
	if err != nil {
		log.Printf("Gagal membuat hash pengguna: %v", err)
		writeError(
			w,
			http.StatusInternalServerError,
			"Gagal memproses kata sandi",
		)
		return
	}

	var user User
	err = a.db.QueryRowContext(r.Context(), `
		INSERT INTO users (username, password_hash, display_name)
		VALUES ($1, $2, $3)
		RETURNING id, username, display_name, is_admin
	`, input.Username, string(hash), input.DisplayName).Scan(
		&user.ID,
		&user.Username,
		&user.DisplayName,
		&user.IsAdmin,
	)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			writeError(
				w,
				http.StatusConflict,
				"Username sudah digunakan",
			)
			return
		}

		log.Printf("Gagal membuat akun: %v", err)
		writeError(
			w,
			http.StatusInternalServerError,
			"Gagal membuat akun",
		)
		return
	}

	writeJSON(w, http.StatusCreated, user)
}

func (a *App) changePassword(
	w http.ResponseWriter,
	r *http.Request,
	user *User,
) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}

	var input struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}

	if err := decodeJSON(w, r, &input); err != nil {
		writeError(w, http.StatusBadRequest, "Format JSON tidak valid")
		return
	}

	if len(input.CurrentPassword) == 0 ||
		len(input.CurrentPassword) > 72 ||
		len(input.NewPassword) < 12 ||
		len(input.NewPassword) > 72 || !utf8.ValidString(input.NewPassword) {
		writeError(
			w,
			http.StatusBadRequest,
			"Kata sandi baru harus 12-72 byte",
		)
		return
	}

	tx, err := a.db.BeginTx(r.Context(), nil)
	if err != nil {
		writeError(
			w,
			http.StatusInternalServerError,
			"Gagal memulai perubahan kata sandi",
		)
		return
	}
	defer tx.Rollback()

	var currentHash string
	err = tx.QueryRowContext(r.Context(), `
		SELECT password_hash
		FROM users
		WHERE id = $1 AND is_active = TRUE
		FOR UPDATE
	`, user.ID).Scan(&currentHash)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeError(w, http.StatusUnauthorized, "Akun tidak aktif")
			return
		}
		log.Printf("Gagal membaca hash kata sandi: %v", err)
		writeError(
			w,
			http.StatusInternalServerError,
			"Gagal memeriksa kata sandi",
		)
		return
	}

	if bcrypt.CompareHashAndPassword(
		[]byte(currentHash),
		[]byte(input.CurrentPassword),
	) != nil {
		writeError(
			w,
			http.StatusUnauthorized,
			"Kata sandi saat ini salah",
		)
		return
	}

	newHash, err := bcrypt.GenerateFromPassword(
		[]byte(input.NewPassword),
		bcrypt.DefaultCost,
	)
	if err != nil {
		writeError(
			w,
			http.StatusInternalServerError,
			"Gagal memproses kata sandi baru",
		)
		return
	}

	_, err = tx.ExecContext(r.Context(), `
		UPDATE users SET password_hash = $1 WHERE id = $2
	`, string(newHash), user.ID)
	if err != nil {
		log.Printf("Gagal mengubah kata sandi: %v", err)
		writeError(
			w,
			http.StatusInternalServerError,
			"Gagal mengubah kata sandi",
		)
		return
	}

	// Cabut seluruh sesi akun setelah perubahan kata sandi.
	_, err = tx.ExecContext(r.Context(), `
		DELETE FROM sessions WHERE user_id = $1
	`, user.ID)
	if err != nil {
		log.Printf("Gagal mencabut sesi: %v", err)
		writeError(
			w,
			http.StatusInternalServerError,
			"Gagal mencabut sesi lama",
		)
		return
	}

	if err := tx.Commit(); err != nil {
		log.Printf("Gagal menyimpan perubahan kata sandi: %v", err)
		writeError(
			w,
			http.StatusInternalServerError,
			"Gagal menyimpan perubahan",
		)
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"message": "Kata sandi berhasil diubah. Silakan login kembali.",
	})
}

func (a *App) users(
	w http.ResponseWriter,
	r *http.Request,
	current *User,
) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}

	rows, err := a.db.QueryContext(r.Context(), `
		SELECT id, username, display_name, is_admin
		FROM users
		WHERE is_active = TRUE
		ORDER BY username
	`)
	if err != nil {
		log.Printf("Gagal mengambil pengguna: %v", err)
		writeError(
			w,
			http.StatusInternalServerError,
			"Gagal mengambil pengguna",
		)
		return
	}
	defer rows.Close()

	users := make([]User, 0)
	for rows.Next() {
		var user User
		if err := rows.Scan(
			&user.ID,
			&user.Username,
			&user.DisplayName,
			&user.IsAdmin,
		); err != nil {
			log.Printf("Gagal membaca pengguna: %v", err)
			writeError(
				w,
				http.StatusInternalServerError,
				"Gagal membaca pengguna",
			)
			return
		}
		users = append(users, user)
	}

	if err := rows.Err(); err != nil {
		log.Printf("Kesalahan hasil query pengguna: %v", err)
		writeError(
			w,
			http.StatusInternalServerError,
			"Gagal membaca pengguna",
		)
		return
	}

	writeJSON(w, http.StatusOK, users)
}

func (a *App) messages(
	w http.ResponseWriter,
	r *http.Request,
	current *User,
) {
	currentID := strconv.FormatInt(current.ID, 10)

	switch r.Method {
	case http.MethodGet:
		rows, err := a.db.QueryContext(r.Context(), `
			SELECT id, sender_id, receiver_id, content, created_at
			FROM messages
			WHERE sender_id = $1 OR receiver_id = $1
			ORDER BY created_at DESC, id DESC
			LIMIT 500
		`, currentID)
		if err != nil {
			log.Printf("Gagal mengambil pesan: %v", err)
			writeError(
				w,
				http.StatusInternalServerError,
				"Gagal mengambil pesan",
			)
			return
		}
		defer rows.Close()

		messages := make([]Message, 0)
		for rows.Next() {
			var message Message
			if err := rows.Scan(
				&message.ID,
				&message.SenderID,
				&message.ReceiverID,
				&message.Content,
				&message.CreatedAt,
			); err != nil {
				log.Printf("Gagal membaca pesan: %v", err)
				writeError(
					w,
					http.StatusInternalServerError,
					"Gagal membaca pesan",
				)
				return
			}
			messages = append(messages, message)
		}

		if err := rows.Err(); err != nil {
			log.Printf("Kesalahan hasil query pesan: %v", err)
			writeError(
				w,
				http.StatusInternalServerError,
				"Gagal membaca pesan",
			)
			return
		}

		// Kembalikan urutan menjadi yang terlama ke terbaru.
		for left, right := 0, len(messages)-1; left < right; left, right = left+1, right-1 {
			messages[left], messages[right] = messages[right], messages[left]
		}

		writeJSON(w, http.StatusOK, messages)

	case http.MethodPost:
		var input struct {
			ReceiverID string `json:"receiver_id"`
			Content    string `json:"content"`
		}

		if err := decodeJSON(w, r, &input); err != nil {
			writeError(w, http.StatusBadRequest, "Format JSON tidak valid")
			return
		}

		input.ReceiverID = strings.TrimSpace(input.ReceiverID)
		input.Content = strings.TrimSpace(input.Content)

		receiverID, err := strconv.ParseInt(input.ReceiverID, 10, 64)
		if err != nil || receiverID <= 0 ||
			!validText(input.Content, 1, 4000) {
			writeError(
				w,
				http.StatusBadRequest,
				"Penerima atau isi pesan tidak valid",
			)
			return
		}

		if receiverID == current.ID {
			writeError(
				w,
				http.StatusBadRequest,
				"Tidak dapat mengirim pesan kepada diri sendiri",
			)
			return
		}

		var active bool
		err = a.db.QueryRowContext(r.Context(), `
			SELECT EXISTS (
				SELECT 1 FROM users
				WHERE id = $1 AND is_active = TRUE
			)
		`, receiverID).Scan(&active)
		if err != nil {
			log.Printf("Gagal memeriksa penerima: %v", err)
			writeError(
				w,
				http.StatusInternalServerError,
				"Gagal memeriksa penerima",
			)
			return
		}

		if !active {
			writeError(
				w,
				http.StatusNotFound,
				"Penerima tidak ditemukan",
			)
			return
		}

		var message Message
		err = a.db.QueryRowContext(r.Context(), `
			INSERT INTO messages (sender_id, receiver_id, content)
			VALUES ($1, $2, $3)
			RETURNING id, sender_id, receiver_id, content, created_at
		`,
			currentID,
			strconv.FormatInt(receiverID, 10),
			input.Content,
		).Scan(
			&message.ID,
			&message.SenderID,
			&message.ReceiverID,
			&message.Content,
			&message.CreatedAt,
		)
		if err != nil {
			log.Printf("Gagal menyimpan pesan: %v", err)
			writeError(
				w,
				http.StatusInternalServerError,
				"Gagal menyimpan pesan",
			)
			return
		}

		writeJSON(w, http.StatusCreated, message)

	default:
		methodNotAllowed(w)
	}
}

func (a *App) routes() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/health", a.health)
	mux.HandleFunc("/login", a.login)
	mux.HandleFunc("/me", a.requireAuth(a.me))
	mux.HandleFunc("/logout", a.requireAuth(a.logout))
	mux.HandleFunc("/register", a.requireAuth(a.register))
	mux.HandleFunc("/change-password", a.requireAuth(a.changePassword))
	mux.HandleFunc("/users", a.requireAuth(a.users))
	mux.HandleFunc("/messages", a.requireAuth(a.messages))

	const allowedOrigin = "https://ruangkita-697.pages.dev"

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")

		origin := r.Header.Get("Origin")
		if origin != "" && origin != allowedOrigin {
			writeError(
				w,
				http.StatusForbidden,
				"Origin tidak diizinkan",
			)
			return
		}

		w.Header().Add("Vary", "Origin")
		if origin == allowedOrigin {
			w.Header().Set("Access-Control-Allow-Origin", allowedOrigin)
			w.Header().Set(
				"Access-Control-Allow-Headers",
				"Authorization, Content-Type",
			)
			w.Header().Set(
				"Access-Control-Allow-Methods",
				"GET, POST, OPTIONS",
			)
		}

		if r.Method == http.MethodOptions {
			if origin != allowedOrigin || r.Header.Get("Access-Control-Request-Method") == "" {
				writeError(w, http.StatusForbidden, "Preflight tidak diizinkan")
				return
			}
			method := r.Header.Get("Access-Control-Request-Method")
			if method != http.MethodGet && method != http.MethodPost {
				writeError(w, http.StatusMethodNotAllowed, "Metode preflight tidak diizinkan")
				return
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}

		mux.ServeHTTP(w, r)
	})
}

func main() {
	dsn, err := databaseDSN()
	if err != nil {
		log.Fatal("Konfigurasi database tidak valid: ", err)
	}

	db, err := sql.Open("pgx", dsn)
	if err != nil {
		log.Fatal("Gagal membuka database: ", err)
	}
	defer db.Close()

	db.SetMaxOpenConns(5)
	db.SetMaxIdleConns(2)
	db.SetConnMaxLifetime(30 * time.Minute)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		log.Fatal("Koneksi PostgreSQL gagal: ", err)
	}

	// Hash dummy dipakai saat username tidak ditemukan.
	dummyHash, err := bcrypt.GenerateFromPassword(
		[]byte("dummy-password-never-used"),
		bcrypt.DefaultCost,
	)
	if err != nil {
		log.Fatal("Gagal menyiapkan pemeriksaan login")
	}

	if err := bootstrapAdmin(db); err != nil {
		log.Fatal("Bootstrap admin gagal: ", err)
	}

	app := &App{
		db:        db,
		dummyHash: dummyHash,
	}

	server := &http.Server{
		Addr:              ":8088",
		Handler:           app.routes(),
		ReadHeaderTimeout: 5 * time.Second,
		MaxHeaderBytes:    16 << 10,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	log.Println("RuangKita backend berjalan di port 8088")
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}
