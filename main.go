
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
	allowedOrigin   = "https://ruangkita-697.pages.dev"
)

var errInvalidSession = errors.New("invalid session")

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
	limiter   *LoginLimiter
}

type attemptRecord struct {
	count      int
	windowEnds time.Time
}

type LoginLimiter struct {
	mu      sync.Mutex
	records map[string]attemptRecord
}

func newLoginLimiter() *LoginLimiter {
	return &LoginLimiter{
		records: make(map[string]attemptRecord),
	}
}

func (l *LoginLimiter) blocked(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	record, ok := l.records[ip]
	if !ok {
		return false
	}
	if !now.Before(record.windowEnds) {
		delete(l.records, ip)
		return false
	}
	return record.count >= maxLoginFails
}

func (l *LoginLimiter) failed(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()

	// Bersihkan entri kedaluwarsa setiap ada kegagalan.
	for key, record := range l.records {
		if !now.Before(record.windowEnds) {
			delete(l.records, key)
		}
	}

	// Batasi jumlah IP yang dapat disimpan dalam memori.
	if len(l.records) >= 5000 {
		if _, exists := l.records[ip]; !exists {
			return
		}
	}

	record, ok := l.records[ip]
	if !ok || !now.Before(record.windowEnds) {
		record = attemptRecord{
			windowEnds: now.Add(loginWindow),
		}
	}

	record.count++
	l.records[ip] = record
}

func (l *LoginLimiter) clear(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.records, ip)
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}

func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{
		"error": message,
	})
}

func methodNotAllowed(w http.ResponseWriter) {
	writeError(w, http.StatusMethodNotAllowed,
		"Metode HTTP tidak diizinkan")
}

func decodeJSON(w http.ResponseWriter, r *http.Request, target any) error {
	if r.Body == nil {
		return errors.New("body kosong")
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)

	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(target); err != nil {
		return err
	}

	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("hanya satu objek JSON diizinkan")
		}
		return err
	}

	return nil
}

func validText(value string, min, max int) bool {
	if !utf8.ValidString(value) {
		return false
	}
	n := utf8.RuneCountInString(strings.TrimSpace(value))
	return n >= min && n <= max
}

func validPassword(password string) bool {
	return utf8.ValidString(password) &&
		len(password) >= 12 &&
		len(password) <= 72
}

func databaseDSN() (string, error) {
	host := strings.TrimSpace(os.Getenv("DB_HOST"))
	port := strings.TrimSpace(os.Getenv("DB_PORT"))
	name := strings.TrimSpace(os.Getenv("DB_NAME"))
	user := os.Getenv("DB_USER")
	password := os.Getenv("DB_PASSWORD")

	if host == "" || port == "" || name == "" ||
		user == "" || password == "" {
		return "", errors.New("konfigurasi database belum lengkap")
	}

	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return "", errors.New("DB_PORT tidak valid")
	}

	sslMode := strings.TrimSpace(os.Getenv("DB_SSLMODE"))
	if sslMode == "" {
		sslMode = "disable"
	}

	switch sslMode {
	case "disable", "require", "verify-ca", "verify-full":
	default:
		return "", errors.New("DB_SSLMODE tidak valid")
	}

	u := url.URL{
		Scheme: "postgres",
		User:   url.UserPassword(user, password),
		Host:   net.JoinHostPort(host, port),
		Path:   name,
	}

	q := u.Query()
	q.Set("sslmode", sslMode)
	u.RawQuery = q.Encode()

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
	values := r.Header.Values("Authorization")
	if len(values) != 1 {
		return "", errInvalidSession
	}

	fields := strings.Fields(values[0])
	if len(fields) != 2 || !strings.EqualFold(fields[0], "Bearer") {
		return "", errInvalidSession
	}

	token := fields[1]
	if len(token) != 64 {
		return "", errInvalidSession
	}

	if _, err := hex.DecodeString(token); err != nil {
		return "", errInvalidSession
	}
	return token, nil
}

func bootstrapAdmin(db *sql.DB) error {
	ctx, cancel := context.WithTimeout(
		context.Background(), 30*time.Second)
	defer cancel()

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("memulai bootstrap: %w", err)
	}
	defer tx.Rollback()

	// PostgreSQL mengembalikan void.
	// Cast ke text agar hasil Scan konsisten.
	var lockResult string
	err = tx.QueryRowContext(ctx,
		`SELECT pg_advisory_xact_lock(736219401)::text`,
	).Scan(&lockResult)
	if err != nil {
		return fmt.Errorf("mengunci bootstrap: %w", err)
	}

	var count int64
	err = tx.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM users`,
	).Scan(&count)
	if err != nil {
		return fmt.Errorf("memeriksa users: %w", err)
	}

	if count > 0 {
		log.Println("Bootstrap dilewati: pengguna sudah tersedia")
		return tx.Commit()
	}

	password := os.Getenv("BOOTSTRAP_ADMIN_PASSWORD")
	if !validPassword(password) {
		return errors.New(
			"BOOTSTRAP_ADMIN_PASSWORD wajib 12-72 byte UTF-8",
		)
	}

	hash, err := bcrypt.GenerateFromPassword(
		[]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("hash admin: %w", err)
	}

	_, err = tx.ExecContext(ctx, `
		INSERT INTO users
			(username, password_hash, display_name, is_admin, is_active)
		VALUES ($1, $2, $3, TRUE, TRUE)
	`, "alin", string(hash), "Alin")
	if err != nil {
		return fmt.Errorf("menyimpan admin: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit bootstrap: %w", err)
	}

	log.Println("Bootstrap admin selesai")
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

	if errors.Is(err, sql.ErrNoRows) {
		return nil, errInvalidSession
	}
	if err != nil {
		return nil, err
	}
	return &user, nil
}

type authenticatedHandler func(
	http.ResponseWriter, *http.Request, *User,
)

func (a *App) requireAuth(next authenticatedHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, err := a.authenticate(r)
		if err != nil {
			if errors.Is(err, errInvalidSession) {
				writeError(w, http.StatusUnauthorized,
					"Sesi tidak valid atau sudah berakhir")
				return
			}
			log.Printf("Autentikasi gagal: %v", err)
			writeError(w, http.StatusInternalServerError,
				"Gagal memeriksa sesi")
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
		writeError(w, http.StatusServiceUnavailable,
			"Database tidak tersedia")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"status": "ok",
	})
}

func (a *App) login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}

	ip := clientIP(r)
	if a.limiter.blocked(ip) {
		writeError(w, http.StatusTooManyRequests,
			"Terlalu banyak percobaan login")
		return
	}

	var input struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := decodeJSON(w, r, &input); err != nil {
		writeError(w, http.StatusBadRequest, "JSON tidak valid")
		return
	}

	input.Username = strings.TrimSpace(input.Username)

	if !validText(input.Username, 1, 50) ||
		!utf8.ValidString(input.Password) ||
		len(input.Password) == 0 ||
		len(input.Password) > 72 {
		a.limiter.failed(ip)
		writeError(w, http.StatusUnauthorized,
			"Username atau kata sandi salah")
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
		_ = bcrypt.CompareHashAndPassword(
			a.dummyHash, []byte(input.Password))
		a.limiter.failed(ip)
		writeError(w, http.StatusUnauthorized,
			"Username atau kata sandi salah")
		return
	}

	if err != nil {
		log.Printf("Query login gagal: %v", err)
		writeError(w, http.StatusInternalServerError,
			"Gagal memproses login")
		return
	}

	if bcrypt.CompareHashAndPassword(
		[]byte(passwordHash), []byte(input.Password)) != nil {
		a.limiter.failed(ip)
		writeError(w, http.StatusUnauthorized,
			"Username atau kata sandi salah")
		return
	}

	token, err := generateToken()
	if err != nil {
		writeError(w, http.StatusInternalServerError,
			"Gagal membuat sesi")
		return
	}

	// Cek ulang status akun pada saat menyimpan sesi.
	result, err := a.db.ExecContext(r.Context(), `
		INSERT INTO sessions (user_id, token_hash, expires_at)
		SELECT id, $2, $3
		FROM users
		WHERE id = $1 AND is_active = TRUE
	`, user.ID, tokenHash(token), time.Now().Add(sessionLifetime))

	if err != nil {
		log.Printf("Simpan sesi gagal: %v", err)
		writeError(w, http.StatusInternalServerError,
			"Gagal menyimpan sesi")
		return
	}

	affected, err := result.RowsAffected()
	if err != nil || affected != 1 {
		writeError(w, http.StatusUnauthorized,
			"Akun tidak aktif")
		return
	}

	a.limiter.clear(ip)

	writeJSON(w, http.StatusOK, map[string]any{
		"token":      token,
		"expires_in": int(sessionLifetime.Seconds()),
		"user":       user,
	})
}

func (a *App) me(w http.ResponseWriter, r *http.Request, user *User) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	writeJSON(w, http.StatusOK, user)
}

func (a *App) logout(w http.ResponseWriter, r *http.Request, user *User) {
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
		DELETE FROM sessions WHERE token_hash = $1
	`, tokenHash(token))
	if err != nil {
		writeError(w, http.StatusInternalServerError,
			"Gagal logout")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"message": "Berhasil logout",
	})
}

func (a *App) register(w http.ResponseWriter, r *http.Request, admin *User) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}

	if !admin.IsAdmin {
		writeError(w, http.StatusForbidden,
			"Hanya admin yang dapat membuat akun")
		return
	}

	var input struct {
		Username    string `json:"username"`
		Password    string `json:"password"`
		DisplayName string `json:"display_name"`
	}

	if err := decodeJSON(w, r, &input); err != nil {
		writeError(w, http.StatusBadRequest, "JSON tidak valid")
		return
	}

	input.Username = strings.TrimSpace(input.Username)
	input.DisplayName = strings.TrimSpace(input.DisplayName)

	if !validText(input.Username, 3, 50) ||
		!validText(input.DisplayName, 1, 100) ||
		!validPassword(input.Password) {
		writeError(w, http.StatusBadRequest,
			"Username, nama, atau kata sandi tidak valid")
		return
	}

	hash, err := bcrypt.GenerateFromPassword(
		[]byte(input.Password), bcrypt.DefaultCost)
	if err != nil {
		writeError(w, http.StatusInternalServerError,
			"Gagal memproses kata sandi")
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
			writeError(w, http.StatusConflict,
				"Username sudah digunakan")
			return
		}

		log.Printf("Registrasi gagal: %v", err)
		writeError(w, http.StatusInternalServerError,
			"Gagal membuat akun")
		return
	}

	writeJSON(w, http.StatusCreated, user)
}

func (a *App) changePassword(
	w http.ResponseWriter, r *http.Request, user *User,
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
		writeError(w, http.StatusBadRequest, "JSON tidak valid")
		return
	}

	if len(input.CurrentPassword) == 0 ||
		len(input.CurrentPassword) > 72 ||
		!validPassword(input.NewPassword) {
		writeError(w, http.StatusBadRequest,
			"Kata sandi tidak valid")
		return
	}

	tx, err := a.db.BeginTx(r.Context(), nil)
	if err != nil {
		writeError(w, http.StatusInternalServerError,
			"Gagal memulai transaksi")
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

	if errors.Is(err, sql.ErrNoRows) {
		writeError(w, http.StatusUnauthorized, "Akun tidak aktif")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError,
			"Gagal membaca akun")
		return
	}

	if bcrypt.CompareHashAndPassword(
		[]byte(currentHash), []byte(input.CurrentPassword)) != nil {
		writeError(w, http.StatusUnauthorized,
			"Kata sandi lama salah")
		return
	}

	if bcrypt.CompareHashAndPassword(
		[]byte(currentHash), []byte(input.NewPassword)) == nil {
		writeError(w, http.StatusBadRequest,
			"Kata sandi baru harus berbeda")
		return
	}

	newHash, err := bcrypt.GenerateFromPassword(
		[]byte(input.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		writeError(w, http.StatusInternalServerError,
			"Gagal membuat hash")
		return
	}

	_, err = tx.ExecContext(r.Context(), `
		UPDATE users SET password_hash = $1 WHERE id = $2
	`, string(newHash), user.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError,
			"Gagal mengganti kata sandi")
		return
	}

	_, err = tx.ExecContext(r.Context(), `
		DELETE FROM sessions WHERE user_id = $1
	`, user.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError,
			"Gagal mencabut sesi")
		return
	}

	if err := tx.Commit(); err != nil {
		writeError(w, http.StatusInternalServerError,
			"Gagal menyimpan perubahan")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"message": "Kata sandi diubah. Silakan login kembali.",
	})
}

func (a *App) users(w http.ResponseWriter, r *http.Request, current *User) {
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
		writeError(w, http.StatusInternalServerError,
			"Gagal mengambil pengguna")
		return
	}
	defer rows.Close()

	result := make([]User, 0)

	for rows.Next() {
		var user User
		if err := rows.Scan(
			&user.ID, &user.Username,
			&user.DisplayName, &user.IsAdmin,
		); err != nil {
			writeError(w, http.StatusInternalServerError,
				"Gagal membaca pengguna")
			return
		}
		result = append(result, user)
	}

	if err := rows.Err(); err != nil {
		writeError(w, http.StatusInternalServerError,
			"Gagal membaca pengguna")
		return
	}

	writeJSON(w, http.StatusOK, result)
}

func (a *App) messages(
	w http.ResponseWriter, r *http.Request, current *User,
) {
	currentID := strconv.FormatInt(current.ID, 10)

	switch r.Method {
	case http.MethodGet:
		a.getMessages(w, r, currentID)
	case http.MethodPost:
		a.sendMessage(w, r, current)
	default:
		methodNotAllowed(w)
	}
}

func (a *App) getMessages(
	w http.ResponseWriter, r *http.Request, currentID string,
) {
	rows, err := a.db.QueryContext(r.Context(), `
		SELECT id, sender_id, receiver_id, content, created_at
		FROM messages
		WHERE sender_id = $1 OR receiver_id = $1
		ORDER BY created_at DESC, id DESC
		LIMIT 500
	`, currentID)
	if err != nil {
		writeError(w, http.StatusInternalServerError,
			"Gagal mengambil pesan")
		return
	}
	defer rows.Close()

	result := make([]Message, 0)

	for rows.Next() {
		var m Message
		if err := rows.Scan(
			&m.ID, &m.SenderID, &m.ReceiverID,
			&m.Content, &m.CreatedAt,
		); err != nil {
			writeError(w, http.StatusInternalServerError,
				"Gagal membaca pesan")
			return
		}
		result = append(result, m)
	}

	if err := rows.Err(); err != nil {
		writeError(w, http.StatusInternalServerError,
			"Gagal membaca pesan")
		return
	}

	for i, j := 0, len(result)-1; i < j; i, j = i+1, j-1 {
		result[i], result[j] = result[j], result[i]
	}

	writeJSON(w, http.StatusOK, result)
}

func (a *App) sendMessage(
	w http.ResponseWriter, r *http.Request, current *User,
) {
	var input struct {
		ReceiverID string `json:"receiver_id"`
		Content    string `json:"content"`
	}

	if err := decodeJSON(w, r, &input); err != nil {
		writeError(w, http.StatusBadRequest, "JSON tidak valid")
		return
	}

	input.ReceiverID = strings.TrimSpace(input.ReceiverID)
	input.Content = strings.TrimSpace(input.Content)

	receiverID, err := strconv.ParseInt(input.ReceiverID, 10, 64)
	if err != nil || receiverID <= 0 ||
		!validText(input.Content, 1, 4000) {
		writeError(w, http.StatusBadRequest,
			"Penerima atau pesan tidak valid")
		return
	}

	if receiverID == current.ID {
		writeError(w, http.StatusBadRequest,
			"Tidak dapat mengirim pesan ke diri sendiri")
		return
	}

	var message Message

	// Validasi penerima aktif dan identitas pengirim
	// dilakukan langsung melalui database.
	err = a.db.QueryRowContext(r.Context(), `
		INSERT INTO messages (sender_id, receiver_id, content)
		SELECT sender.id::text, receiver.id::text, $3
		FROM users sender
		CROSS JOIN users receiver
		WHERE sender.id = $1
		  AND sender.is_active = TRUE
		  AND receiver.id = $2
		  AND receiver.is_active = TRUE
		RETURNING id, sender_id, receiver_id, content, created_at
	`, current.ID, receiverID, input.Content).Scan(
		&message.ID,
		&message.SenderID,
		&message.ReceiverID,
		&message.Content,
		&message.CreatedAt,
	)

	if errors.Is(err, sql.ErrNoRows) {
		writeError(w, http.StatusNotFound,
			"Pengirim atau penerima tidak aktif")
		return
	}

	if err != nil {
		log.Printf("Simpan pesan gagal: %v", err)
		writeError(w, http.StatusInternalServerError,
			"Gagal menyimpan pesan")
		return
	}

	writeJSON(w, http.StatusCreated, message)
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

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Vary", "Origin")

		origin := r.Header.Get("Origin")

		if origin != "" && origin != allowedOrigin {
			writeError(w, http.StatusForbidden,
				"Origin tidak diizinkan")
			return
		}

		if origin == allowedOrigin {
			w.Header().Set("Access-Control-Allow-Origin", allowedOrigin)
			w.Header().Set("Access-Control-Allow-Headers",
				"Authorization, Content-Type")
			w.Header().Set("Access-Control-Allow-Methods",
				"GET, POST, OPTIONS")
			w.Header().Set("Access-Control-Max-Age", "600")
		}

		if r.Method == http.MethodOptions {
			if origin != allowedOrigin {
				writeError(w, http.StatusForbidden,
					"Preflight tidak diizinkan")
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

	ctx, cancel := context.WithTimeout(
		context.Background(), 10*time.Second)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		log.Fatal("Koneksi PostgreSQL gagal")
	}

	dummyHash, err := bcrypt.GenerateFromPassword(
		[]byte("dummy-password-never-used"),
		bcrypt.DefaultCost,
	)
	if err != nil {
		log.Fatal("Gagal menyiapkan autentikasi")
	}

	if err := bootstrapAdmin(db); err != nil {
		log.Fatal("Bootstrap admin gagal: ", err)
	}

	app := &App{
		db:        db,
		dummyHash: dummyHash,
		limiter:   newLoginLimiter(),
	}

	server := &http.Server{
		Addr:              ":8088",
		Handler:           app.routes(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}

	log.Println("RuangKita API siap di port 8088")

	if err := server.ListenAndServe(); err != nil &&
		!errors.Is(err, http.ErrServerClosed) {
		log.Fatal("HTTP server gagal: ", err)
	}
}
