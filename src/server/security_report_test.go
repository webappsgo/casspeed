package server

import (
	"context"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"github.com/casapps/casspeed/src/server/store"
)

func newSecurityReportService(t *testing.T) (*SecurityReportService, *store.SQLiteStore) {
	t.Helper()
	db, err := store.NewSQLiteStore(":memory:")
	if err != nil {
		t.Fatalf("create security report store: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	installationSecret := make([]byte, 32)
	encryptionKey := make([]byte, 32)
	if _, err := rand.Read(installationSecret); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(encryptionKey); err != nil {
		t.Fatal(err)
	}
	service, err := NewSecurityReportService(db, installationSecret, encryptionKey, 365)
	if err != nil {
		t.Fatalf("create security report service: %v", err)
	}
	return service, db
}

func validSecurityReport(now time.Time) SecurityReportInput {
	return SecurityReportInput{
		ResearcherName: "Researcher", ResearcherEmail: "researcher@example.net", Component: "API", Severity: "high",
		Summary: "Authorization check bypass", Steps: "1. Send request", Impact: "Read private results", DisclosureDays: 90,
		CreditPreference: "handle", CreditHandle: "researcher", DisclosureAgreed: true, Timestamp: now.UTC().Format(time.RFC3339),
	}
}

func TestSecurityIDRotatesEvery48HoursAndAcceptsPreviousWindow(t *testing.T) {
	service, _ := newSecurityReportService(t)
	start := time.Unix(1_800_000_000, 0).UTC()
	boundary := time.Unix((start.Unix()/securityIDWindowSeconds+1)*securityIDWindowSeconds, 0).UTC()
	id := service.SecurityID(start)
	if !service.ValidSecurityID(id, boundary) {
		t.Fatal("previous-window security id should remain valid")
	}
	if service.SecurityID(start) == service.SecurityID(boundary) {
		t.Fatal("security id must rotate at the 48-hour boundary")
	}
	if service.ValidSecurityID("not-a-valid-id", start) {
		t.Fatal("malformed security id should be rejected")
	}
}

func TestSecurityReportSubmissionEncryptsBodyAndAllowsSingleDailyStatusRead(t *testing.T) {
	service, db := newSecurityReportService(t)
	ctx := context.Background()
	now := time.Date(2026, time.June, 15, 12, 0, 0, 0, time.UTC)
	trackingID, token, err := service.SubmitInput(ctx, service.SecurityID(now), validSecurityReport(now), now)
	if err != nil {
		t.Fatalf("submit security report: %v", err)
	}
	if !strings.HasPrefix(trackingID, "sec_") || len(trackingID) != 20 || len(token) != 64 {
		t.Fatalf("unexpected report identifiers: %q / token length %d", trackingID, len(token))
	}
	record, err := db.GetSecurityReport(ctx, trackingID)
	if err != nil || record == nil {
		t.Fatalf("load stored report: %#v, %v", record, err)
	}
	if record.BodyAlg != "aes-256-gcm" || strings.Contains(string(record.BodyEnc), "Authorization check bypass") || strings.Contains(string(record.ContactEnc), "researcher@example.net") {
		t.Fatal("report content or contact data was stored without encryption")
	}
	first, err := service.ConsumeStatusToken(ctx, trackingID, token, now)
	if err != nil || first.Status != "received" || first.TrackingID != trackingID {
		t.Fatalf("first status read = %#v, %v", first, err)
	}
	if _, err := service.ConsumeStatusToken(ctx, trackingID, token, now.Add(time.Hour)); err == nil {
		t.Fatal("status token should only be usable once per UTC day")
	}
	if second, err := service.ConsumeStatusToken(ctx, trackingID, token, now.Add(24*time.Hour)); err != nil || second == nil {
		t.Fatalf("status token should be usable on the next day: %#v, %v", second, err)
	}
	if _, err := service.ConsumeStatusToken(ctx, trackingID, strings.Repeat("0", 64), now.Add(48*time.Hour)); err == nil {
		t.Fatal("incorrect status token should fail")
	}
}

func TestSecurityReportAdminViewAndForwardOnlyState(t *testing.T) {
	service, _ := newSecurityReportService(t)
	ctx := context.Background()
	now := time.Now().UTC()
	trackingID, _, err := service.SubmitInput(ctx, service.SecurityID(now), validSecurityReport(now), now)
	if err != nil {
		t.Fatal(err)
	}
	view, err := service.DecryptedAdminReport(ctx, trackingID)
	if err != nil || view["report"] == nil || view["researcher"] == nil {
		t.Fatalf("admin report view = %#v, %v", view, err)
	}
	if err := service.UpdateStatus(ctx, trackingID, "triaged", "critical", "Confirmed for investigation", nil, now.Add(time.Minute)); err != nil {
		t.Fatalf("advance report state: %v", err)
	}
	if err := service.UpdateStatus(ctx, trackingID, "received", "high", "", nil, now.Add(2*time.Minute)); err == nil {
		t.Fatal("backwards status transition should be rejected")
	}
	if err := service.UpdateStatus(ctx, trackingID, "disclosed", "critical", "Fixed and released", nil, now.Add(3*time.Minute)); err != nil {
		t.Fatalf("disclose report: %v", err)
	}
	if err := service.UpdateStatus(ctx, trackingID, "patching", "critical", "", nil, now.Add(4*time.Minute)); err == nil {
		t.Fatal("closed report should not transition")
	}
	if err := service.UpdateStatus(ctx, trackingID, "received", "low", strings.Repeat("x", 2001), nil, now.Add(5*time.Minute)); err == nil {
		t.Fatal("oversized researcher comment should be rejected")
	}
}

func TestSecurityReportInputValidationAndContactAdapter(t *testing.T) {
	service, _ := newSecurityReportService(t)
	now := time.Now().UTC()
	invalid := validSecurityReport(now)
	invalid.ResearcherGPG = "http://example.net/key.asc"
	if _, _, err := service.SubmitInput(context.Background(), service.SecurityID(now), invalid, now); err == nil {
		t.Fatal("non-HTTPS GPG URL should be rejected")
	}
	fields := map[string]string{
		"name": "Researcher", "email": "researcher@example.net", "affected_component": "API", "severity": "medium",
		"vulnerability_summary": "Issue", "steps_to_reproduce": "Reproduce", "impact": "Unauthorized access", "credit_preference": "no", "coordinated_disclosure": "true",
	}
	trackingID, statusURL, err := service.Submit(context.Background(), service.SecurityID(now), fields, "test-agent")
	if err != nil || !strings.HasPrefix(trackingID, "sec_") || !strings.Contains(statusURL, "/server/security/report/") || !strings.Contains(statusURL, "token=") {
		t.Fatalf("contact adapter = %q %q %v", trackingID, statusURL, err)
	}
}

func TestSecurityReportConstructorRequiresPersistedSecrets(t *testing.T) {
	if _, err := NewSecurityReportService(nil, nil, nil, 365); err == nil {
		t.Fatal("constructor should fail closed without store and key material")
	}
}

func TestInvalidSecurityIDFingerprintDoesNotEchoSuppliedValue(t *testing.T) {
	provided := "super-secret-id"
	fingerprint := InvalidSecurityIDFingerprint(provided)
	if fingerprint == provided || len(fingerprint) != 8 {
		t.Fatalf("unexpected security id fingerprint: %q", fingerprint)
	}
}
