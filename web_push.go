package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	webpush "github.com/SherClockHolmes/webpush-go"
)

// Keys are configured only on the staging backend; never expose the private key.
type pushConfig struct{ public, private, subject string }

func loadPushConfig() *pushConfig {
	c := &pushConfig{strings.TrimSpace(os.Getenv("VAPID_PUBLIC_KEY")), strings.TrimSpace(os.Getenv("VAPID_PRIVATE_KEY")), strings.TrimSpace(os.Getenv("VAPID_SUBJECT"))}
	if c.public == "" || c.private == "" || c.subject == "" {
		log.Print("Web Push dinonaktifkan: konfigurasi VAPID belum lengkap")
		return nil
	}
	if !strings.HasPrefix(c.subject, "mailto:") && !strings.HasPrefix(c.subject, "https://") {
		log.Print("Web Push dinonaktifkan: VAPID_SUBJECT harus mailto: atau https://")
		return nil
	}
	return c
}

func (a *App) pushKey(w http.ResponseWriter, r *http.Request, u *User) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	if a.push == nil {
		writeError(w, 503, "Web Push belum dikonfigurasi")
		return
	}
	writeJSON(w, 200, map[string]string{"public_key": a.push.public})
}
func validPushEndpoint(endpoint string) bool {
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Fragment != "" || u.Port() != "" || len(endpoint) > 4096 {
		return false
	}
	host := strings.ToLower(u.Hostname())
	// Prevent authenticated users from making the worker contact arbitrary internal hosts.
	switch host {
	case "fcm.googleapis.com", "updates.push.services.mozilla.com", "push.services.mozilla.com", "web.push.apple.com":
		return true
	default:
		return false
	}
}
func (a *App) pushSubscription(w http.ResponseWriter, r *http.Request, u *User) {
	if a.push == nil {
		writeError(w, 503, "Web Push belum dikonfigurasi")
		return
	}
	var input struct {
		Endpoint string `json:"endpoint"`
		Keys     struct {
			P256dh string `json:"p256dh"`
			Auth   string `json:"auth"`
		} `json:"keys"`
	}
	if r.Method != http.MethodPost && r.Method != http.MethodDelete {
		methodNotAllowed(w)
		return
	}
	if err := decodeJSON(w, r, &input); err != nil || !validPushEndpoint(input.Endpoint) {
		writeError(w, 400, "Subscription tidak valid")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	if r.Method == http.MethodDelete {
		_, err := a.db.ExecContext(ctx, `DELETE FROM push_subscriptions WHERE endpoint=$1 AND user_id=$2`, input.Endpoint, u.ID)
		if err != nil {
			writeError(w, 500, "Gagal menghapus subscription")
			return
		}
		writeJSON(w, 200, map[string]string{"status": "ok"})
		return
	}
	if len(input.Keys.P256dh) < 10 || len(input.Keys.P256dh) > 1024 || len(input.Keys.Auth) < 10 || len(input.Keys.Auth) > 1024 {
		writeError(w, 400, "Kunci subscription tidak valid")
		return
	}
	// One endpoint can only belong to one account. Switching accounts transfers ownership.
	_, err := a.db.ExecContext(ctx, `INSERT INTO push_subscriptions(user_id,endpoint,p256dh,auth_secret,user_agent)
 VALUES($1,$2,$3,$4,$5) ON CONFLICT(endpoint) DO UPDATE SET user_id=EXCLUDED.user_id,p256dh=EXCLUDED.p256dh,auth_secret=EXCLUDED.auth_secret,user_agent=EXCLUDED.user_agent,updated_at=NOW()`, u.ID, input.Endpoint, input.Keys.P256dh, input.Keys.Auth, r.UserAgent())
	if err != nil {
		log.Printf("push subscription: %v", err)
		writeError(w, 500, "Gagal menyimpan subscription")
		return
	}
	writeJSON(w, 200, map[string]string{"status": "ok"})
}

type pushSendFunc func([]byte, *webpush.Subscription, *webpush.Options) (*http.Response, error)

// Claim work using a short database lease; no lock is held during network requests.
type pushJob struct {
	id, recipient int64
	kind, key     string
	sender        sql.NullInt64
	attempts      int
}

func (a *App) claimPushJob(ctx context.Context) (*pushJob, error) {
	var j pushJob
	err := a.db.QueryRowContext(ctx, `WITH next AS (
 SELECT id FROM push_outbox WHERE attempts < 5 AND ((status='pending' AND available_at<=NOW()) OR (status='processing' AND lease_until<NOW()))
 ORDER BY available_at,id FOR UPDATE SKIP LOCKED LIMIT 1)
 UPDATE push_outbox o SET status='processing',attempts=o.attempts+1,lease_until=NOW()+INTERVAL '90 seconds'
 FROM next WHERE o.id=next.id RETURNING o.id,o.recipient_id,o.event_type,o.event_key,o.sender_id,o.attempts`).Scan(&j.id, &j.recipient, &j.kind, &j.key, &j.sender, &j.attempts)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &j, nil
}
func (a *App) processPushJob(ctx context.Context, j *pushJob) error {
	// Snapshot currently registered devices once per job. Existing successful deliveries
	// remain marked sent when a later device fails and the job is retried.
	_, err := a.db.ExecContext(ctx, `INSERT INTO push_deliveries(outbox_id,subscription_id)
 SELECT $1,id FROM push_subscriptions WHERE user_id=$2
 ON CONFLICT DO NOTHING`, j.id, j.recipient)
	if err != nil {
		return err
	}
	rows, err := a.db.QueryContext(ctx, `SELECT d.subscription_id,s.endpoint,s.p256dh,s.auth_secret
 FROM push_deliveries d JOIN push_subscriptions s ON s.id=d.subscription_id
 WHERE d.outbox_id=$1 AND d.status='pending' AND s.user_id=$2`, j.id, j.recipient)
	if err != nil {
		return err
	}
	type sub struct {
		id                     int64
		endpoint, p256dh, auth string
	}
	var subs []sub
	for rows.Next() {
		var v sub
		if err = rows.Scan(&v.id, &v.endpoint, &v.p256dh, &v.auth); err != nil {
			break
		}
		subs = append(subs, v)
	}
	if err == nil {
		err = rows.Err()
	}
	if closeErr := rows.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	title := "RuangKita · Pesan baru"
	switch j.kind {
	case "media":
		title = "RuangKita · Media baru"
	case "sticker":
		title = "RuangKita · Stiker baru"
	}
	payload, _ := json.Marshal(map[string]string{"title": title, "body": "Buka RuangKita untuk melihat pesan.", "tag": fmt.Sprintf("rk-%s-%s", j.kind, j.key), "url": "/"})
	var transient error
	for _, v := range subs {
		if err = ctx.Err(); err != nil {
			return err
		}
		subscription := &webpush.Subscription{Endpoint: v.endpoint, Keys: webpush.Keys{P256dh: v.p256dh, Auth: v.auth}}
		// Real delivery honors the worker context; tests can inject a fake sender.
		sender := a.pushSender
		if sender == nil {
			sender = func(payload []byte, subscription *webpush.Subscription, options *webpush.Options) (*http.Response, error) {
				return webpush.SendNotificationWithContext(ctx, payload, subscription, options)
			}
		}
		resp, sendErr := sender(payload, subscription, &webpush.Options{
			Subscriber: a.push.subject, VAPIDPublicKey: a.push.public, VAPIDPrivateKey: a.push.private, TTL: 60})
		if sendErr != nil {
			transient = sendErr
			continue
		}
		if resp == nil {
			transient = fmt.Errorf("push provider returned nil response")
			continue
		}
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		switch {
		case resp.StatusCode == 404 || resp.StatusCode == 410:
			_, err = a.db.ExecContext(ctx, `DELETE FROM push_subscriptions WHERE id=$1 AND user_id=$2`, v.id, j.recipient)
		case resp.StatusCode == 429 || resp.StatusCode >= 500:
			transient = fmt.Errorf("push provider status %d", resp.StatusCode)
			continue
		case resp.StatusCode >= 400:
			_, err = a.db.ExecContext(ctx, `UPDATE push_deliveries SET status='failed',last_error=$3 WHERE outbox_id=$1 AND subscription_id=$2`, j.id, v.id, fmt.Sprintf("HTTP %d", resp.StatusCode))
		default:
			_, err = a.db.ExecContext(ctx, `UPDATE push_deliveries SET status='sent',last_error=NULL WHERE outbox_id=$1 AND subscription_id=$2`, j.id, v.id)
			if err == nil {
				_, err = a.db.ExecContext(ctx, `UPDATE push_subscriptions SET last_success_at=NOW() WHERE id=$1`, v.id)
			}
		}
		if err != nil {
			return err
		}
	}
	return transient
}
func (a *App) startPushWorker(ctx context.Context) {
	if a.push == nil {
		return
	}
	go func() {
		ticker := time.NewTicker(3 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				workCtx, cancel := context.WithTimeout(ctx, 35*time.Second)
				j, err := a.claimPushJob(workCtx)
				if err == nil && j != nil {
					err = a.processPushJob(workCtx, j)
					if err == nil {
						_, err = a.db.ExecContext(workCtx, `UPDATE push_outbox SET status='sent',completed_at=NOW(),lease_until=NULL,last_error=NULL WHERE id=$1 AND status='processing' AND attempts=$2`, j.id, j.attempts)
					} else {
						status := "pending"
						if j.attempts >= 5 {
							status = "failed"
						}
						_, updateErr := a.db.ExecContext(workCtx, `UPDATE push_outbox SET status=$2,lease_until=NULL,available_at=NOW()+($3::INTEGER*INTERVAL '1 minute'),last_error=$4 WHERE id=$1 AND status='processing' AND attempts=$5`, j.id, status, j.attempts*j.attempts, truncatePushError(err), j.attempts)
						if updateErr != nil {
							log.Printf("Push retry update: %v", updateErr)
						}
					}
				}
				if err != nil && !errors.Is(err, context.Canceled) {
					log.Printf("Push worker: %v", err)
				}
				cancel()
			}
		}
	}()
}
func truncatePushError(err error) string {
	s := err.Error()
	if len(s) > 250 {
		s = s[:250]
	}
	return s
}
