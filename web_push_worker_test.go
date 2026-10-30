package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"

	webpush "github.com/SherClockHolmes/webpush-go"
	_ "github.com/jackc/pgx/v5/stdlib"
)

func TestValidPushEndpoint(t *testing.T) {
	cases := []struct {
		endpoint string
		want     bool
	}{
		{"https://fcm.googleapis.com/fcm/send/abc", true},
		{"https://updates.push.services.mozilla.com/wpush/v2/abc", true},
		{"http://fcm.googleapis.com/send/abc", false},
		{"https://localhost/test", false},
		{"https://fcm.googleapis.com:8443/test", false},
		{"https://fcm.googleapis.com@evil.example/test", false},
	}
	for _, tc := range cases {
		if got := validPushEndpoint(tc.endpoint); got != tc.want {
			t.Errorf("endpoint %q: got %v want %v", tc.endpoint, got, tc.want)
		}
	}
}

func TestTruncatePushError(t *testing.T) {
	if got := truncatePushError(errors.New(strings.Repeat("x", 300))); len(got) != 250 {
		t.Fatalf("got length %d", len(got))
	}
}

// Run only against the dedicated disposable Web Push database. This test inserts
// fixtures and cleans them up; it never contacts a real push provider.
func TestPushWorkerRetryIntegration(t *testing.T) {
	if os.Getenv("RUANGKITA_RUN_PUSH_WORKER_INTEGRATION") != "1" {
		t.Skip("opt-in only")
	}
	const allowed = "ruangkita_v4_webpush_test"
	if os.Getenv("DB_NAME") != allowed {
		t.Fatalf("refusing database other than %s", allowed)
	}
	dsn, err := databaseDSN()
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	var actual string
	if err = db.QueryRowContext(ctx, "SELECT current_database()").Scan(&actual); err != nil || actual != allowed {
		t.Fatalf("unsafe database %q: %v", actual, err)
	}
	// The test must not run in parallel. A dedicated pair of users is created
	// and cleaned by cascading deletes, including jobs and delivery rows.
	var aID, bID, jobID, goodID, badID int64
	prefix := fmt.Sprintf("push_worker_%d", os.Getpid())
	defer func() {
		for _, id := range []int64{aID, bID} {
			if id != 0 {
				_, _ = db.ExecContext(context.Background(), "DELETE FROM users WHERE id=$1", id)
			}
		}
	}()
	for _, v := range []struct {
		suffix string
		id     *int64
	}{{"a", &aID}, {"b", &bID}} {
		if err = db.QueryRowContext(ctx, `INSERT INTO users(username,password_hash,display_name) VALUES($1,'test-only','WebPush Worker Test') RETURNING id`, prefix+v.suffix).Scan(v.id); err != nil {
			t.Fatal(err)
		}
	}
	if err = db.QueryRowContext(ctx, `INSERT INTO push_outbox(recipient_id,event_type,event_key,sender_id) VALUES($1,'message',$2,$3) RETURNING id`, bID, prefix, aID).Scan(&jobID); err != nil {
		t.Fatal(err)
	}
	endpointGood := "https://fcm.googleapis.com/fcm/send/worker-good-" + prefix
	endpointBad := "https://fcm.googleapis.com/fcm/send/worker-bad-" + prefix
	for _, v := range []struct {
		endpoint string
		id       *int64
	}{{endpointGood, &goodID}, {endpointBad, &badID}} {
		if err = db.QueryRowContext(ctx, `INSERT INTO push_subscriptions(user_id,endpoint,p256dh,auth_secret) VALUES($1,$2,'fake-test-key','fake-test-auth') RETURNING id`, bID, v.endpoint).Scan(v.id); err != nil {
			t.Fatal(err)
		}
	}
	attempts := map[string]int{}
	failBad := true
	app := &App{db: db, push: &pushConfig{public: "test", private: "test", subject: "mailto:test@example.com"}}
	app.pushSender = func(_ []byte, s *webpush.Subscription, _ *webpush.Options) (*http.Response, error) {
		attempts[s.Endpoint]++
		if s.Endpoint == endpointBad && failBad {
			return nil, errors.New("temporary provider failure")
		}
		return &http.Response{StatusCode: 201, Body: io.NopCloser(strings.NewReader("ok"))}, nil
	}
	job, err := app.claimPushJob(ctx)
	if err != nil || job == nil || job.id != jobID {
		t.Fatalf("claim: job=%+v err=%v", job, err)
	}
	if err = app.processPushJob(ctx, job); err == nil {
		t.Fatal("expected transient error on first delivery")
	}
	var goodStatus, badStatus string
	if err = db.QueryRowContext(ctx, "SELECT status FROM push_deliveries WHERE outbox_id=$1 AND subscription_id=$2", jobID, goodID).Scan(&goodStatus); err != nil {
		t.Fatal(err)
	}
	if err = db.QueryRowContext(ctx, "SELECT status FROM push_deliveries WHERE outbox_id=$1 AND subscription_id=$2", jobID, badID).Scan(&badStatus); err != nil {
		t.Fatal(err)
	}
	if goodStatus != "sent" || badStatus != "pending" {
		t.Fatalf("statuses good=%s bad=%s", goodStatus, badStatus)
	}
	failBad = false
	if err = app.processPushJob(ctx, job); err != nil {
		t.Fatal(err)
	}
	if attempts[endpointGood] != 1 || attempts[endpointBad] != 2 {
		t.Fatalf("unexpected sends: good=%d bad=%d", attempts[endpointGood], attempts[endpointBad])
	}
	if err = db.QueryRowContext(ctx, "SELECT status FROM push_deliveries WHERE outbox_id=$1 AND subscription_id=$2", jobID, badID).Scan(&badStatus); err != nil || badStatus != "sent" {
		t.Fatalf("retry status=%s err=%v", badStatus, err)
	}
}
