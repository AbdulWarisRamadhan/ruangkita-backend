
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

	"github.com/jackc/pgx/v5/stdlib"
	"golang.org/x/crypto/bcrypt"
)

const (
	sessionDuration = 7 * 24 * time.Hour
	maxJSONBody     = 1 << 20 // 1 MB
)

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
	db *sql.DB
}

type contextKey string

const userContextKey contextKey = "authenticated_user"

var loginAttempts = struct {
	sync.Mutex
	counts map[string]int
}{
	counts: make(map[string]int),
}

func jsonResponse(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func errorResponse(w http.ResponseWriter, status int, message string) {
	jsonResponse(w, status, map[string]string{"error": message})
}

func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxJSONBody)

	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(dst); err != nil {
		return err
	}

	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("hanya boleh ada satu objek JSON")
		}
		return err
	}

	return nil
}

func requiredString(value string, min, max int) bool {
	value = strings.TrimSpace(value)
	return len(value) >= min && len(value) <= max
}

func methodNotAllowed(w http.ResponseWriter) {
	errorResponse(w, http.StatusMethodNotAllowed, "Metode HTTP tidak diizinkan")
}

func databaseURL() (string, error) {
	host := strings.TrimSpace(os.Getenv("DB_HOST"))
	port := strings.TrimSpace(os.Getenv("DB_PORT"))
	name := strings.TrimSpace(os.Getenv("DB_NAME"))
	user := os.Getenv("DB_USER")
	password := os.Getenv("DB_PASSWORD")

	if host == "" || port == "" || name == "" || user == "" || password == "" {
		return "", errors.New("DB_HOST, DB_PORT, DB_NAME, DB_USER, dan DB_PASSWORD wajib diatur")
	}

	u := url.URL{
		Scheme: "postgres",
		User:   url.UserPassword(user, password),
		Host:   net.JoinHostPort(host, port),
		Path:   name,
	}

	q := u.Query()
	q.Set("sslmode", "disable")
	u.RawQuery = q.Encode()

	return u.String(), nil
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func newToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func bootstrapAdmin(db *sql.DB) error {
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&count); err != nil {
		return fmt.Errorf("memeriksa akun pengguna: %w", err)
	}

	// Admin awal hanya dibuat jika tabel users benar-benar kosong.
	if count > 0 {
		log.Println("Bootstrap admin dilewati: pengguna sudah tersedia")
		return nil
	}

	password := os.Getenv("BOOTSTRAP_ADMIN_PASSWORD")
	if len(password) < 12 {
		return errors.New(
			"tabel users masih kosong: atur BOOTSTRAP_ADMIN_PASSWORD " +
				"dengan kata sandi awal minimal 12 karakter",
		)
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("membuat hash kata sandi admin: %w", err)
	}

	_, err = db.Exec(`
		INSERT INTO users (username, password_hash, display_name, is_admin, is_active)
		VALUES ($1, $2, $3, TRUE, TRUE)
		ON CONFLICT (username) DO NOTHING
	`, "alin", string(hash), "Alin")
	if err != nil {
		return fmt.Errorf("membuat admin awal: %w", err)
	}

	log.Println("Bootstrap admin selesai")
	return nil
}

func (a *App) authenticate(r *http.Request) (*User, error) {
	header := r.Header.Get("Authorization")
	if !strings.HasPrefix(header, "Bearer ") {
		return nil, errors.New("token tidak tersedia")
	}

	token := strings.TrimSpace(strings.TrimPrefix(header, "Bearer "))
	if len(token) != 64 {
		return nil, errors.New("token tidak valid")
	}

	var user User
	err := a.db.QueryRowContext(r.Context(), `
		SELECT u.id, u.username, u.display_name, u.is_admin
		FROM sessions s
		JOIN users u ON u.id = s.user_id
		WHERE s.token_hash = $1
		  AND s.expires_at > NOW()
		  AND u.is_active = TRUE
	`, hashToken(token)).Scan(
		&user.ID, &user.Username, &user.DisplayName, &user.IsAdmin,
	)

	if err != nil {
		return nil, err
	}

	return &user, nil
}

type authenticatedHandler func(http.ResponseWriter, *http.Request, *User)

func (a *App) requireAuth(handler authenticatedHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, err := a.authenticate(r)
		if err != nil {
			errorResponse(w, http.StatusUnauthorized, "Sesi tidak valid atau sudah berakhir")
			return
		}

		handler(w, r, user)
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
		errorResponse(w, http.StatusServiceUnavailable, "Database tidak tersedia")
		return
	}

	jsonResponse(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (a *App) login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}

	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		ip = r.RemoteAddr
	}

	loginAttempts.Lock()
	if loginAttempts.counts[ip] >= 10 {
		loginAttempts.Unlock()
		errorResponse(w, http.StatusTooManyRequests, "Terlalu banyak percobaan login")
		return
	}
	loginAttempts.Unlock()

	var input struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := decodeJSON(w, r, &input); err != nil {
		errorResponse(w, http.StatusBadRequest, "Format JSON tidak valid")
		return
	}

	input.Username = strings.TrimSpace(input.Username)
	if !requiredString(input.Username, 1, 50) ||
		len(input.Password) == 0 || len(input.Password) > 128 {
		errorResponse(w, http.StatusBadRequest, "Username atau kata sandi tidak valid")
		return
	}

	var user User
	var passwordHash string

	err = a.db.QueryRowContext(r.Context(), `
		SELECT id, username, display_name, is_admin, password_hash
		FROM users
		WHERE username = $1 AND is_active = TRUE
	`, input.Username).Scan(
		&user.ID, &user.Username, &user.DisplayName, &user.IsAdmin, &passwordHash,
	)

	if err != nil || bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(input.Password)) != nil {
		loginAttempts.Lock()
		loginAttempts.counts[ip]++
		loginAttempts.Unlock()
		errorResponse(w, http.StatusUnauthorized, "Username atau kata sandi salah")
		return
	}

	token, err := newToken()
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, "Gagal membuat sesi")
		return
	}

	_, err = a.db.ExecContext(r.Context(), `
		INSERT INTO sessions (user_id, token_hash, expires_at)
		VALUES ($1, $2, $3)
	`, user.ID, hashToken(token), time.Now().Add(sessionDuration))

	if err != nil {
		errorResponse(w, http.StatusInternalServerError, "Gagal menyimpan sesi")
		return
	}

	loginAttempts.Lock()
	delete(loginAttempts.counts, ip)
	loginAttempts.Unlock()

	jsonResponse(w, http.StatusOK, map[string]any{
		"token":      token,
		"expires_in": int(sessionDuration.Seconds()),
		"user":       user,
	})
}

func (a *App) me(w http.ResponseWriter, r *http.Request, user *User) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	jsonResponse(w, http.StatusOK, user)
}

func (a *App) logout(w http.ResponseWriter, r *http.Request, user *User) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}

	token := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	_, err := a.db.ExecContext(r.Context(),
		`DELETE FROM sessions WHERE token_hash = $1`, hashToken(token))
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, "Gagal mengakhiri sesi")
		return
	}

	jsonResponse(w, http.StatusOK, map[string]string{"message": "Berhasil logout"})
}

func (a *App) register(w http.ResponseWriter, r *http.Request, admin *User) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	if !admin.IsAdmin {
		errorResponse(w, http.StatusForbidden, "Hanya admin yang dapat membuat akun")
		return
	}

	var input struct {
		Username    string `json:"username"`
		Password    string `json:"password"`
		DisplayName string `json:"display_name"`
	}

	if err := decodeJSON(w, r, &input); err != nil {
		errorResponse(w, http.StatusBadRequest, "Format JSON tidak valid")
		return
	}

	input.Username = strings.TrimSpace(input.Username)
	input.DisplayName = strings.TrimSpace(input.DisplayName)

	if !requiredString(input.Username, 3, 50) ||
		!requiredString(input.DisplayName, 1, 100) ||
		len(input.Password) < 12 || len(input.Password) > 72 {
		errorResponse(w, http.StatusBadRequest,
			"Username harus 3-50 karakter, nama 1-100 karakter, dan kata sandi 12-72 byte")
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(input.Password), bcrypt.DefaultCost)
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, "Gagal memproses kata sandi")
		return
	}

	var user User
	err = a.db.QueryRowContext(r.Context(), `
		INSERT INTO users (username, password_hash, display_name)
		VALUES ($1, $2, $3)
		RETURNING id, username, display_name, is_admin
	`, input.Username, string(hash), input.DisplayName).Scan(
		&user.ID, &user.Username, &user.DisplayName, &user.IsAdmin,
	)
	if err != nil {
		errorResponse(w, http.StatusConflict, "Gagal membuat akun; username mungkin sudah digunakan")
		return
	}

	jsonResponse(w, http.StatusCreated, user)
}

func (a *App) changePassword(w http.ResponseWriter, r *http.Request, user *User) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}

	var input struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}

	if err := decodeJSON(w, r, &input); err != nil {
		errorResponse(w, http.StatusBadRequest, "Format JSON tidak valid")
		return
	}

	if len(input.CurrentPassword) == 0 ||
		len(input.NewPassword) < 12 || len(input.NewPassword) > 72 {
		errorResponse(w, http.StatusBadRequest, "Kata sandi baru harus 12-72 byte")
		return
	}

	var currentHash string
	err := a.db.QueryRowContext(r.Context(),
		`SELECT password_hash FROM users WHERE id = $1 AND is_active = TRUE`,
		user.ID).Scan(&currentHash)

	if err != nil ||
		bcrypt.CompareHashAndPassword([]byte(currentHash), []byte(input.CurrentPassword)) != nil {
		errorResponse(w, http.StatusUnauthorized, "Kata sandi saat ini salah")
		return
	}

	newHash, err := bcrypt.GenerateFromPassword([]byte(input.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, "Gagal memproses kata sandi")
		return
	}

	tx, err := a.db.BeginTx(r.Context(), nil)
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, "Gagal memulai transaksi")
		return
	}
	defer tx.Rollback()

	if _, err = tx.ExecContext(r.Context(),
		`UPDATE users SET password_hash = $1 WHERE id = $2`,
		string(newHash), user.ID); err != nil {
		errorResponse(w, http.StatusInternalServerError, "Gagal mengubah kata sandi")
		return
	}

	// Semua sesi dicabut; pengguna harus login kembali.
	if _, err = tx.ExecContext(r.Context(),
		`DELETE FROM sessions WHERE user_id = $1`, user.ID); err != nil {
		errorResponse(w, http.StatusInternalServerError, "Gagal mencabut sesi")
		return
	}

	if err = tx.Commit(); err != nil {
		errorResponse(w, http.StatusInternalServerError, "Gagal menyimpan perubahan")
		return
	}

	jsonResponse(w, http.StatusOK, map[string]string{
		"message": "Kata sandi berhasil diubah. Silakan login kembali.",
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
		errorResponse(w, http.StatusInternalServerError, "Gagal mengambil pengguna")
		return
	}
	defer rows.Close()

	users := make([]User, 0)
	for rows.Next() {
		var user User
		if err := rows.Scan(&user.ID, &user.Username, &user.DisplayName, &user.IsAdmin); err != nil {
			errorResponse(w, http.StatusInternalServerError, "Gagal membaca pengguna")
			return
		}
		users = append(users, user)
	}
	if err := rows.Err(); err != nil {
		errorResponse(w, http.StatusInternalServerError, "Gagal membaca pengguna")
		return
	}

	jsonResponse(w, http.StatusOK, users)
}

func (a *App) messages(w http.ResponseWriter, r *http.Request, current *User) {
	switch r.Method {
	case http.MethodGet:
		rows, err := a.db.QueryContext(r.Context(), `
			SELECT id, sender_id, receiver_id, content, created_at
			FROM messages
			WHERE sender_id = $1 OR receiver_id = $1
			ORDER BY created_at ASC
			LIMIT 500
		`, strconv.FormatInt(current.ID, 10))
		if err != nil {
			errorResponse(w, http.StatusInternalServerError, "Gagal mengambil pesan")
			return
		}
		defer rows.Close()

		messages := make([]Message, 0)
		for rows.Next() {
			var message Message
			if err := rows.Scan(
				&message.ID, &message.SenderID, &message.ReceiverID,
				&message.Content, &message.CreatedAt,
			); err != nil {
				errorResponse(w, http.StatusInternalServerError, "Gagal membaca pesan")
				return
			}
			messages = append(messages, message)
		}
		if err := rows.Err(); err != nil {
			errorResponse(w, http.StatusInternalServerError, "Gagal membaca pesan")
			return
		}

		jsonResponse(w, http.StatusOK, messages)

	case http.MethodPost:
		var input struct {
			ReceiverID string `json:"receiver_id"`
			Content    string `json:"content"`
		}

		if err := decodeJSON(w, r, &input); err != nil {
			errorResponse(w, http.StatusBadRequest, "Format JSON tidak valid")
			return
		}

		input.ReceiverID = strings.TrimSpace(input.ReceiverID)
		input.Content = strings.TrimSpace(input.Content)

		receiverID, err := strconv.ParseInt(input.ReceiverID, 10, 64)
		if err != nil || receiverID <= 0 ||
			!requiredString(input.Content, 1, 4000) {
			errorResponse(w, http.StatusBadRequest, "Penerima atau isi pesan tidak valid")
			return
		}
		if receiverID == current.ID {
			errorResponse(w, http.StatusBadRequest, "Tidak dapat mengirim pesan kepada diri sendiri")
			return
		}

		var active bool
		err = a.db.QueryRowContext(r.Context(),
			`SELECT EXISTS(SELECT 1 FROM users WHERE id = $1 AND is_active = TRUE)`,
			receiverID).Scan(&active)
		if err != nil {
			errorResponse(w, http.StatusInternalServerError, "Gagal memeriksa penerima")
			return
		}
		if !active {
			errorResponse(w, http.StatusNotFound, "Penerima tidak ditemukan")
			return
		}

		var message Message
		err = a.db.QueryRowContext(r.Context(), `
			INSERT INTO messages (sender_id, receiver_id, content)
			VALUES ($1, $2, $3)
			RETURNING id, sender_id, receiver_id, content, created_at
		`,
			strconv.FormatInt(current.ID, 10),
			strconv.FormatInt(receiverID, 10),
			input.Content,
		).Scan(
			&message.ID, &message.SenderID, &message.ReceiverID,
			&message.Content, &message.CreatedAt,
		)
		if err != nil {
			errorResponse(w, http.StatusInternalServerError, "Gagal menyimpan pesan")
			return
		}

		jsonResponse(w, http.StatusCreated, message)

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

	allowedOrigin := "https://ruangkita-697.pages.dev"

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")

		if origin != "" && origin != allowedOrigin {
			errorResponse(w, http.StatusForbidden, "Origin tidak diizinkan")
			return
		}

		if origin == allowedOrigin {
			w.Header().Set("Access-Control-Allow-Origin", allowedOrigin)
			w.Header().Set("Vary", "Origin")
			w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		}

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		mux.ServeHTTP(w, r)
	})
}

func main() {
	dbURL, err := databaseURL()
	if err != nil {
		log.Fatal(err)
	}

	// Registrasi driver pgx untuk database/sql.
	_ = stdlib.GetDefaultDriver()

	db, err := sql.Open("pgx", dbURL)
	if err != nil {
		log.Fatal("Gagal membuka konfigurasi database: ", err)
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

	if err := bootstrapAdmin(db); err != nil {
		log.Fatal("Bootstrap admin gagal: ", err)
	}

	app := &App{db: db}

	server := &http.Server{
		Addr:              ":8088",
		Handler:           app.routes(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	log.Println("RuangKita backend berjalan di port 8088")
	log.Fatal(server.ListenAndServe())
}
