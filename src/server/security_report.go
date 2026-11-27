package server

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/mail"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/casapps/casspeed/src/server/model"
	"github.com/casapps/casspeed/src/server/store"
)

const securityIDWindowSeconds int64 = 48 * 60 * 60

var errSecurityReportNotFound = errors.New("security report not found")
var errSecurityReportInvalid = errors.New("invalid security report")
var errSecurityStatusUnavailable = errors.New("security report status is unavailable")
var errSecurityTransition = errors.New("invalid security report status transition")
var securityReportURLPattern = regexp.MustCompile(`(?i)(?:https?://|www\.)\S+`)

// SecurityReportService persists encrypted coordinated-disclosure reports.
// Secrets must be generated and persisted by server initialization, then passed here.
type SecurityReportService struct {
	store              securityReportStore
	installationSecret []byte
	encryptionKey      []byte
	retentionDays      int
	securityLog        func(string, map[string]any)
	csrfSecret         []byte
	projectKeypair     *SecurityKeypairManager
}

type securityReportStore interface {
	CreateSecurityReport(context.Context, store.SecurityReportRecord) error
	GetSecurityReport(context.Context, string) (*store.SecurityReportRecord, error)
	ListSecurityReports(context.Context, string, int, int) ([]store.SecurityReportRecord, error)
	UpdateSecurityReport(context.Context, store.SecurityReportRecord, string) error
	ConsumeSecurityStatusToken(context.Context, string, string, string) (*store.SecurityReportRecord, error)
	CleanupSecurityReports(context.Context, time.Time) (int64, error)
	ListSecurityThanks(context.Context) ([]store.SecurityThanksRecord, error)
	GetAdminSession(context.Context, string) (*model.AdminSession, error)
	GetAdminUsername(context.Context, int) (string, error)
	UpdateAdminSessionActivity(context.Context, string) error
}

// SecurityReportInput is the validated report submitted by a researcher.
type SecurityReportInput struct {
	ResearcherName   string `json:"name"`
	ResearcherEmail  string `json:"email"`
	ResearcherGPG    string `json:"researcher_gpg"`
	Component        string `json:"component"`
	Endpoint         string `json:"endpoint"`
	Severity         string `json:"severity"`
	Summary          string `json:"summary"`
	Steps            string `json:"steps"`
	Impact           string `json:"impact"`
	SuggestedFix     string `json:"suggested_fix"`
	CVERequested     bool   `json:"cve_requested"`
	DisclosureDays   int    `json:"disclosure_days"`
	CreditPreference string `json:"credit_preference"`
	CreditHandle     string `json:"credit_handle"`
	DisclosureAgreed bool   `json:"disclosure_agreed"`
	AppVersion       string `json:"app_version"`
	CommitHash       string `json:"commit_hash"`
	Timestamp        string `json:"timestamp"`
	RequestUserAgent string `json:"request_user_agent"`
}

// SecurityReportStatus contains the only report fields exposed to its researcher.
type SecurityReportStatus struct {
	TrackingID        string     `json:"tracking_id"`
	Status            string     `json:"status"`
	ResearcherComment string     `json:"researcher_comment"`
	DisclosureDate    *time.Time `json:"disclosure_date,omitempty"`
}

// NewSecurityReportService requires cluster-wide installation and AES keys.
func NewSecurityReportService(st securityReportStore, installationSecret, encryptionKey []byte, retentionDays int) (*SecurityReportService, error) {
	if st == nil || len(installationSecret) < 32 || len(encryptionKey) != 32 {
		return nil, errors.New("security report store and 32-byte secrets are required")
	}
	if retentionDays <= 0 {
		retentionDays = 365
	}
	return &SecurityReportService{store: st, installationSecret: append([]byte(nil), installationSecret...), encryptionKey: append([]byte(nil), encryptionKey...), retentionDays: retentionDays, csrfSecret: append([]byte(nil), installationSecret...)}, nil
}

// SecurityID returns the deterministic id for the current 48-hour window.
func (s *SecurityReportService) SecurityID(now time.Time) string {
	return s.securityID(now.Unix() / securityIDWindowSeconds)
}

// SetProjectKeypairManager enables PGP encryption for incoming report bodies.
func (s *SecurityReportService) SetProjectKeypairManager(manager *SecurityKeypairManager) {
	s.projectKeypair = manager
}

// PGPKeyHandler serves the project's public key when publication is configured.
func (s *SecurityReportService) PGPKeyHandler(w http.ResponseWriter, r *http.Request) {
	if s.projectKeypair == nil {
		http.NotFound(w, r)
		return
	}
	s.projectKeypair.PGPKeyHandler(w, r)
}

func (s *SecurityReportService) securityID(window int64) string {
	mac := hmac.New(sha256.New, s.installationSecret)
	_, _ = fmt.Fprintf(mac, "%d", window)
	return hex.EncodeToString(mac.Sum(nil))[:16]
}

// ValidSecurityID accepts the current and immediately previous 48-hour windows.
func (s *SecurityReportService) ValidSecurityID(id string, now time.Time) bool {
	if len(id) != 16 {
		return false
	}
	if _, err := hex.DecodeString(id); err != nil {
		return false
	}
	window := now.Unix() / securityIDWindowSeconds
	current := s.securityID(window)
	previous := s.securityID(window - 1)
	return subtle.ConstantTimeCompare([]byte(id), []byte(current)) == 1 || subtle.ConstantTimeCompare([]byte(id), []byte(previous)) == 1
}

// InvalidSecurityIDFingerprint returns a safe, short fingerprint for security.log.
func InvalidSecurityIDFingerprint(id string) string {
	digest := sha256.Sum256([]byte(id))
	return hex.EncodeToString(digest[:])[:8]
}

// Submit validates and encrypts a report before writing it. The returned status token
// is shown only to the caller so it can be delivered in the private acknowledgment link.
func (s *SecurityReportService) SubmitInput(ctx context.Context, securityID string, input SecurityReportInput, now time.Time) (trackingID, statusToken string, err error) {
	if !s.ValidSecurityID(securityID, now) {
		return "", "", errSecurityReportInvalid
	}
	if err := validateSecurityReportInput(&input); err != nil {
		return "", "", err
	}
	idBytes := make([]byte, 8)
	if _, err := io.ReadFull(rand.Reader, idBytes); err != nil {
		return "", "", fmt.Errorf("generate report id: %w", err)
	}
	tokenBytes := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, tokenBytes); err != nil {
		return "", "", fmt.Errorf("generate status token: %w", err)
	}
	trackingID = "sec_" + hex.EncodeToString(idBytes)
	statusToken = hex.EncodeToString(tokenBytes)
	body, err := json.Marshal(input)
	if err != nil {
		return "", "", fmt.Errorf("encode report body: %w", err)
	}
	bodyAlg := "aes-256-gcm"
	var bodyEnc []byte
	if s.projectKeypair != nil {
		metadata, metadataErr := s.projectKeypair.Metadata(ctx)
		if metadataErr != nil {
			return "", "", fmt.Errorf("load project key metadata: %w", metadataErr)
		}
		if metadata != nil && !metadata.Revoked {
			bodyEnc, err = s.projectKeypair.Encrypt(body)
			if err != nil {
				return "", "", fmt.Errorf("encrypt report body with project key: %w", err)
			}
			bodyAlg = "pgp"
		}
	}
	if bodyEnc == nil {
		bodyEnc, err = s.encrypt(body)
		if err != nil {
			return "", "", fmt.Errorf("encrypt report body: %w", err)
		}
	}
	contact, err := json.Marshal(map[string]string{"name": input.ResearcherName, "email": input.ResearcherEmail, "gpg": input.ResearcherGPG})
	if err != nil {
		return "", "", fmt.Errorf("encode report contact: %w", err)
	}
	contactEnc, err := s.encrypt(contact)
	if err != nil {
		return "", "", fmt.Errorf("encrypt report contact: %w", err)
	}
	tokenHash := sha256.Sum256([]byte(statusToken))
	window := now.Unix() / securityIDWindowSeconds
	record := store.SecurityReportRecord{
		TrackingID: trackingID, IDWindow: window, Severity: strings.ToLower(input.Severity), Component: input.Component,
		Status: "received", BodyEnc: bodyEnc, BodyAlg: bodyAlg, ContactEnc: contactEnc,
		CreditPreference: creditPreferenceCode(input.CreditPreference), CreditName: securityCreditName(input), CVERequested: input.CVERequested,
		TokenHash: hex.EncodeToString(tokenHash[:]), CreatedAt: now.UTC(), UpdatedAt: now.UTC(),
	}
	if err := s.store.CreateSecurityReport(ctx, record); err != nil {
		return "", "", fmt.Errorf("save encrypted security report: %w", err)
	}
	return trackingID, statusToken, nil
}

func validateSecurityReportInput(input *SecurityReportInput) error {
	fields := []struct {
		name     string
		value    *string
		max      int
		required bool
	}{
		{"name", &input.ResearcherName, 100, true}, {"email", &input.ResearcherEmail, 254, true},
		{"researcher_gpg", &input.ResearcherGPG, 16384, false}, {"component", &input.Component, 255, true},
		{"endpoint", &input.Endpoint, 2048, false}, {"severity", &input.Severity, 16, true}, {"summary", &input.Summary, 200, true},
		{"steps", &input.Steps, 10000, true}, {"impact", &input.Impact, 5000, true}, {"suggested_fix", &input.SuggestedFix, 5000, false},
		{"credit_preference", &input.CreditPreference, 16, true}, {"credit_handle", &input.CreditHandle, 100, false},
	}
	for _, field := range fields {
		*field.value = strings.TrimSpace(*field.value)
		if field.required && *field.value == "" {
			return fmt.Errorf("%w: %s is required", errSecurityReportInvalid, field.name)
		}
		if utf8.RuneCountInString(*field.value) > field.max {
			limit := field.max
			if field.name == "researcher_gpg" && strings.HasPrefix(*field.value, "https://") {
				limit = 2048
			}
			if utf8.RuneCountInString(*field.value) > limit {
				return fmt.Errorf("%w: %s exceeds %d characters", errSecurityReportInvalid, field.name, limit)
			}
		}
	}
	address, err := mail.ParseAddress(input.ResearcherEmail)
	if err != nil || address.Address != input.ResearcherEmail {
		return fmt.Errorf("%w: email is invalid", errSecurityReportInvalid)
	}
	if input.ResearcherGPG != "" && strings.HasPrefix(input.ResearcherGPG, "https://") {
		parsed, err := url.ParseRequestURI(input.ResearcherGPG)
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
			return fmt.Errorf("%w: researcher_gpg URL is invalid", errSecurityReportInvalid)
		}
	} else if input.ResearcherGPG != "" && !strings.Contains(input.ResearcherGPG, "-----BEGIN PGP PUBLIC KEY BLOCK-----") {
		return fmt.Errorf("%w: researcher_gpg must be an HTTPS URL or armored public key", errSecurityReportInvalid)
	}
	if !containsFold([]string{"critical", "high", "medium", "low", "informational"}, input.Severity) {
		return fmt.Errorf("%w: severity is invalid", errSecurityReportInvalid)
	}
	if input.DisclosureDays == 0 {
		input.DisclosureDays = 90
	}
	if input.DisclosureDays < 1 || input.DisclosureDays > 365 {
		return fmt.Errorf("%w: disclosure_days must be from 1 to 365", errSecurityReportInvalid)
	}
	if !containsFold([]string{"real name", "handle", "no", "anonymous"}, input.CreditPreference) {
		return fmt.Errorf("%w: credit_preference is invalid", errSecurityReportInvalid)
	}
	if strings.EqualFold(input.CreditPreference, "handle") && input.CreditHandle == "" {
		return fmt.Errorf("%w: credit_handle is required", errSecurityReportInvalid)
	}
	if !input.DisclosureAgreed {
		return fmt.Errorf("%w: coordinated disclosure agreement is required", errSecurityReportInvalid)
	}
	return nil
}

func containsFold(options []string, value string) bool {
	for _, option := range options {
		if strings.EqualFold(option, value) {
			return true
		}
	}
	return false
}

func creditPreferenceCode(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "real name":
		return "name"
	case "handle":
		return "handle"
	case "anonymous":
		return "anon"
	default:
		return "no"
	}
}

func securityCreditName(input SecurityReportInput) *string {
	var name string
	switch creditPreferenceCode(input.CreditPreference) {
	case "name":
		name = input.ResearcherName
	case "handle":
		name = input.CreditHandle
	default:
		return nil
	}
	return &name
}

func (s *SecurityReportService) encrypt(plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(s.encryptionKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, []byte("casspeed-security-report-v1")), nil
}

func (s *SecurityReportService) decrypt(ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(s.encryptionKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < gcm.NonceSize() {
		return nil, errors.New("encrypted report is truncated")
	}
	nonce, body := ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():]
	return gcm.Open(nil, nonce, body, []byte("casspeed-security-report-v1"))
}

// ConsumeStatusToken verifies a link token and permits one status read per UTC day.
func (s *SecurityReportService) ConsumeStatusToken(ctx context.Context, trackingID, token string, now time.Time) (*SecurityReportStatus, error) {
	if len(token) != 64 {
		return nil, errSecurityStatusUnavailable
	}
	hash := sha256.Sum256([]byte(token))
	record, err := s.store.GetSecurityReport(ctx, trackingID)
	if err != nil || record == nil {
		return nil, errSecurityStatusUnavailable
	}
	storedHash, err := hex.DecodeString(record.TokenHash)
	if err != nil || subtle.ConstantTimeCompare(storedHash, hash[:]) != 1 {
		return nil, errSecurityStatusUnavailable
	}
	record, err = s.store.ConsumeSecurityStatusToken(ctx, trackingID, hex.EncodeToString(hash[:]), now.UTC().Format("2006-01-02"))
	if err != nil || record == nil {
		return nil, errSecurityStatusUnavailable
	}
	if (record.Status == "disclosed" || record.Status == "wont_fix") && now.After(record.ClosedAt.Add(30*24*time.Hour)) {
		return nil, errSecurityStatusUnavailable
	}
	status := &SecurityReportStatus{TrackingID: record.TrackingID, Status: record.Status, ResearcherComment: record.ResearcherComment, DisclosureDate: record.DisclosureDate}
	return status, nil
}

// DecryptedAdminReport returns report contents only for a caller that has already authenticated as a server admin.
func (s *SecurityReportService) DecryptedAdminReport(ctx context.Context, trackingID string) (map[string]any, error) {
	record, err := s.store.GetSecurityReport(ctx, trackingID)
	if err != nil {
		return nil, err
	}
	if record == nil {
		return nil, errSecurityReportNotFound
	}
	var body []byte
	if record.BodyAlg == "pgp" {
		if s.projectKeypair == nil {
			return nil, errors.New("project OpenPGP key manager is unavailable")
		}
		body, err = s.projectKeypair.Decrypt(record.BodyEnc)
	} else if record.BodyAlg == "aes-256-gcm" {
		body, err = s.decrypt(record.BodyEnc)
	} else {
		return nil, errors.New("security report uses an unsupported encryption algorithm")
	}
	if err != nil {
		return nil, fmt.Errorf("decrypt security report %s: %w", trackingID, err)
	}
	contact, err := s.decrypt(record.ContactEnc)
	if err != nil {
		return nil, fmt.Errorf("decrypt security report contact %s: %w", trackingID, err)
	}
	var report map[string]any
	var researcher map[string]string
	if err := json.Unmarshal(body, &report); err != nil {
		return nil, fmt.Errorf("decode security report: %w", err)
	}
	if err := json.Unmarshal(contact, &researcher); err != nil {
		return nil, fmt.Errorf("decode security report contact: %w", err)
	}
	return map[string]any{"record": record, "report": report, "researcher": researcher}, nil
}

// UpdateStatus changes an authenticated operator's report triage state.
func (s *SecurityReportService) UpdateStatus(ctx context.Context, trackingID, status, severity, comment string, disclosureDate *time.Time, now time.Time) error {
	record, err := s.store.GetSecurityReport(ctx, trackingID)
	if err != nil {
		return err
	}
	if record == nil {
		return errSecurityReportNotFound
	}
	status = strings.ToLower(strings.TrimSpace(status))
	severity = strings.ToLower(strings.TrimSpace(severity))
	if !containsFold([]string{"received", "triaged", "confirmed", "patching", "disclosed", "wont_fix"}, status) || !containsFold([]string{"critical", "high", "medium", "low", "informational"}, severity) || utf8.RuneCountInString(comment) > 2000 {
		return errSecurityReportInvalid
	}
	if statusRank(status) < statusRank(record.Status) && status != "wont_fix" {
		return errSecurityTransition
	}
	if record.Status == "disclosed" || record.Status == "wont_fix" {
		return errSecurityTransition
	}
	oldStatus := record.Status
	record.Status = status
	record.Severity = severity
	record.ResearcherComment = strings.TrimSpace(comment)
	record.DisclosureDate = disclosureDate
	record.UpdatedAt = now.UTC()
	if status == "disclosed" || status == "wont_fix" {
		closedAt := now.UTC()
		record.ClosedAt = &closedAt
	}
	return s.store.UpdateSecurityReport(ctx, *record, oldStatus)
}

func statusRank(status string) int {
	switch status {
	case "received":
		return 0
	case "triaged":
		return 1
	case "confirmed":
		return 2
	case "patching":
		return 3
	case "disclosed", "wont_fix":
		return 4
	default:
		return -1
	}
}

// Cleanup removes closed reports after the configured retention period.
func (s *SecurityReportService) Cleanup(ctx context.Context, now time.Time) (int64, error) {
	return s.store.CleanupSecurityReports(ctx, now.UTC().AddDate(0, 0, -s.retentionDays))
}

// Submit adapts contact form values to the validated security-report pipeline.
// The returned relative status URL contains the one-time status token and must only
// be sent to the submitted researcher email, never included in a response or log.
func (s *SecurityReportService) Submit(ctx context.Context, securityID string, fields map[string]string, userAgent string) (string, string, error) {
	parseBool := func(value string) bool {
		return strings.EqualFold(strings.TrimSpace(value), "true") || value == "1" || strings.EqualFold(value, "on")
	}
	days := 90
	if raw := strings.TrimSpace(fields["disclosure_days"]); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil {
			return "", "", fmt.Errorf("%w: disclosure_days is invalid", errSecurityReportInvalid)
		}
		days = parsed
	}
	input := SecurityReportInput{
		ResearcherName: fields["name"], ResearcherEmail: fields["email"], ResearcherGPG: fields["researcher_gpg"],
		Component: fields["affected_component"], Endpoint: fields["affected_endpoint"], Severity: fields["severity"], Summary: fields["vulnerability_summary"],
		Steps: fields["steps_to_reproduce"], Impact: fields["impact"], SuggestedFix: fields["suggested_fix"], CVERequested: parseBool(fields["cve_requested"]),
		DisclosureDays: days, CreditPreference: fields["credit_preference"], CreditHandle: fields["credit_handle"],
		DisclosureAgreed: parseBool(fields["coordinated_disclosure"]), RequestUserAgent: userAgent, Timestamp: time.Now().UTC().Format(time.RFC3339),
	}
	trackingID, token, err := s.SubmitInput(ctx, securityID, input, time.Now())
	if err != nil {
		return "", "", err
	}
	return trackingID, "/server/security/report/" + url.PathEscape(trackingID) + "?token=" + url.QueryEscape(token), nil
}

// SetSecurityLogger installs metadata-only security event logging from server initialization.
func (s *SecurityReportService) SetSecurityLogger(logEvent func(string, map[string]any)) {
	s.securityLog = logEvent
}

// LogReportReceived emits the required metadata-only event after the contact
// adapter has attempted the private researcher acknowledgment.
func (s *SecurityReportService) LogReportReceived(ctx context.Context, trackingID string, notified bool) {
	if s.securityLog == nil {
		return
	}
	record, err := s.store.GetSecurityReport(ctx, trackingID)
	if err != nil || record == nil {
		return
	}
	component := securityReportURLPattern.ReplaceAllString(strings.Join(strings.Fields(record.Component), " "), "[url]")
	component = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, component)
	if utf8.RuneCountInString(component) > 255 {
		component = string([]rune(component)[:255])
	}
	s.securityLog("security.report_received", map[string]any{"tracking_id": record.TrackingID, "notified": notified, "severity": record.Severity, "component": component})
}

// ListSecurityThanks returns only public, disclosed credit entries.
func (s *SecurityReportService) ListSecurityThanks(ctx context.Context) ([]store.SecurityThanksRecord, error) {
	return s.store.ListSecurityThanks(ctx)
}

// LogInvalidSecurityID records a one-way fingerprint and request metadata only.
func (s *SecurityReportService) LogInvalidSecurityID(id, remoteAddress, userAgent string) {
	if s.securityLog == nil {
		return
	}
	if len(userAgent) > 512 {
		userAgent = userAgent[:512]
	}
	s.securityLog("security.invalid_id", map[string]any{"id_fingerprint": InvalidSecurityIDFingerprint(id), "ip": peerIP(remoteAddress), "user_agent": userAgent})
}

// SetCSRFSecret installs the independently persisted CSRF HMAC secret.
func (s *SecurityReportService) SetCSRFSecret(secret []byte) error {
	if len(secret) != 32 {
		return errors.New("CSRF secret must be 32 bytes")
	}
	s.csrfSecret = append([]byte(nil), secret...)
	return nil
}

func (s *SecurityReportService) adminCSRFToken(sessionID string) string {
	mac := hmac.New(sha256.New, s.csrfSecret)
	_, _ = mac.Write([]byte("casspeed-admin-csrf\x00" + sessionID))
	return hex.EncodeToString(mac.Sum(nil))
}

func validAdminCSRFToken(sessionID, cookieToken, formToken, expected string) bool {
	if sessionID == "" || len(cookieToken) != 64 || len(formToken) != 64 || len(expected) != 64 {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(cookieToken), []byte(formToken)) == 1 && subtle.ConstantTimeCompare([]byte(cookieToken), []byte(expected)) == 1
}

func isSameOriginRequest(r *http.Request) bool {
	if strings.EqualFold(strings.TrimSpace(r.Header.Get("Sec-Fetch-Site")), "cross-site") {
		return false
	}
	requestOrigin, err := url.Parse(BuildURL(r, "/"))
	if err != nil || requestOrigin.Scheme == "" || requestOrigin.Host == "" {
		return false
	}
	source := strings.TrimSpace(r.Header.Get("Origin"))
	if source == "" {
		source = strings.TrimSpace(r.Header.Get("Referer"))
	}
	if source == "" || strings.EqualFold(source, "null") {
		return false
	}
	sourceURL, err := url.Parse(source)
	if err != nil || sourceURL.Scheme == "" || sourceURL.Host == "" {
		return false
	}
	return strings.EqualFold(sourceURL.Scheme, requestOrigin.Scheme) && strings.EqualFold(sourceURL.Host, requestOrigin.Host)
}

func (s *SecurityReportService) logCSRFFailure(r *http.Request, reason string) {
	if s.securityLog != nil {
		s.securityLog("security.csrf_failure", map[string]any{"ip": peerIP(r.RemoteAddr), "endpoint": r.URL.Path, "reason": reason})
	}
}

// StatusPageHandler serves the one-use-per-day researcher status page. It exposes no report content.
func (s *SecurityReportService) StatusPageHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		serverAuthError(w, r, http.StatusMethodNotAllowed, "auth.pages.security_method_not_allowed")
		return
	}
	w.Header().Set("Cache-Control", "private, no-store")
	w.Header().Set("X-Robots-Tag", "noindex, nofollow")
	w.Header().Set("Referrer-Policy", "no-referrer")
	trackingID := strings.TrimPrefix(requestRoutePath(r), "/server/security/report/")
	trackingID = strings.TrimSpace(trackingID)
	status, err := s.ConsumeStatusToken(r.Context(), trackingID, r.URL.Query().Get("token"), time.Now())
	if err != nil {
		http.NotFound(w, r)
		return
	}
	catalogStatus := securityStatusLabel(r, status.Status)
	language, direction := requestLanguage(r)
	data := struct {
		Lang, Dir, BasePath, Title, Skip, TrackingLabel, StatusLabel, MessageLabel, DisclosureLabel string
		TrackingID, Status, Comment, DisclosureDate                                                 string
	}{
		Lang: language, Dir: direction, BasePath: requestPathPrefix(r),
		Title: serverAuthText(r, "auth.pages.security_status_title"), Skip: serverAuthText(r, "nav.skip_to_content"),
		TrackingLabel: serverAuthText(r, "auth.pages.security_tracking_id"), StatusLabel: serverAuthText(r, "auth.pages.security_status"),
		MessageLabel: serverAuthText(r, "auth.pages.security_service_message"), DisclosureLabel: serverAuthText(r, "auth.pages.security_disclosure_date"),
		TrackingID: status.TrackingID, Status: catalogStatus, Comment: status.ResearcherComment,
	}
	if status.DisclosureDate != nil {
		data.DisclosureDate = status.DisclosureDate.UTC().Format("2006-01-02")
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := securityStatusTemplate.Execute(w, data); err != nil {
		serverAuthError(w, r, http.StatusInternalServerError, "auth.pages.security_render_failed")
	}
}

var securityStatusTemplate = template.Must(template.New("security-status").Parse(`<!doctype html><html lang="{{.Lang}}" dir="{{.Dir}}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow"><title>{{.Title}}</title><link rel="stylesheet" href="{{.BasePath}}/static/css/style.css"></head><body><a class="skip-link" href="#main-content">{{.Skip}}</a><main id="main-content" class="container container-md"><h1>{{.Title}}</h1><p>{{.TrackingLabel}}: <code>{{.TrackingID}}</code></p><p>{{.StatusLabel}}: <strong>{{.Status}}</strong></p>{{if .Comment}}<section><h2>{{.MessageLabel}}</h2><p>{{.Comment}}</p></section>{{end}}{{if .DisclosureDate}}<p>{{.DisclosureLabel}}: <time>{{.DisclosureDate}}</time></p>{{end}}</main></body></html>`))

func securityStatusLabel(r *http.Request, status string) string {
	key := map[string]string{
		"received": "security_status_received", "triaged": "security_status_triaged", "confirmed": "security_status_confirmed",
		"patching": "security_status_patching", "disclosed": "security_status_disclosed", "wont_fix": "security_status_wont_fix",
	}[status]
	if key == "" {
		key = "security_status_received"
	}
	return serverAuthText(r, "auth.pages."+key)
}

func securitySeverityLabel(r *http.Request, severity string) string {
	key := "security_severity_" + strings.ToLower(strings.TrimSpace(severity))
	if !map[string]bool{"security_severity_critical": true, "security_severity_high": true, "security_severity_medium": true, "security_severity_low": true, "security_severity_informational": true}[key] {
		return severity
	}
	return serverAuthText(r, "auth.pages."+key)
}

// AdminReportsHandler serves the admin report list and requires a valid admin session cookie.
func (s *SecurityReportService) AdminReportsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		serverAuthError(w, r, http.StatusMethodNotAllowed, "auth.pages.security_method_not_allowed")
		return
	}
	adminName, _, ok := s.requireSecurityAdmin(w, r)
	if !ok {
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	reports, err := s.store.ListSecurityReports(r.Context(), r.URL.Query().Get("status"), limit, offset)
	if err != nil {
		serverAuthError(w, r, http.StatusInternalServerError, "auth.pages.security_load_failed")
		return
	}
	rows := make([]securityReportListItem, 0, len(reports))
	for _, report := range reports {
		item := securityReportListItem{TrackingID: report.TrackingID, Severity: securitySeverityLabel(r, report.Severity), Status: securityStatusLabel(r, report.Status), Component: report.Component, CreatedAt: report.CreatedAt.UTC().Format(time.RFC3339)}
		if body, err := s.decryptReportBody(r.Context(), report); err == nil {
			var input SecurityReportInput
			if json.Unmarshal(body, &input) == nil {
				item.Summary = input.Summary
			}
		}
		rows = append(rows, item)
	}
	if s.securityLog != nil {
		s.securityLog("security.reports_listed", map[string]any{"admin": adminName, "count": len(rows)})
	}
	w.Header().Set("Cache-Control", "private, no-store")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	base := strings.TrimSuffix(r.URL.Path, "/")
	language, direction := requestLanguage(r)
	labels := map[string]string{
		"title": serverAuthText(r, "auth.pages.security_reports_title"), "skip": serverAuthText(r, "nav.skip_to_content"),
		"status": serverAuthText(r, "auth.pages.security_status"), "all": serverAuthText(r, "auth.pages.security_all"),
		"filter": serverAuthText(r, "auth.pages.security_filter"), "tracking": serverAuthText(r, "auth.pages.security_tracking_id"),
		"summary": serverAuthText(r, "auth.pages.security_summary"), "severity": serverAuthText(r, "auth.pages.security_severity"),
		"state": serverAuthText(r, "auth.pages.security_state"), "component": serverAuthText(r, "auth.pages.security_component"),
		"received": serverAuthText(r, "auth.pages.security_received"), "empty": serverAuthText(r, "auth.pages.security_no_reports"),
	}
	statuses := []string{"received", "triaged", "confirmed", "patching", "disclosed", "wont_fix"}
	statusOptions := make([]securityReportOption, 0, len(statuses))
	for _, value := range statuses {
		statusOptions = append(statusOptions, securityReportOption{Value: value, Label: securityStatusLabel(r, value)})
	}
	data := struct {
		Rows                              []securityReportListItem
		Status, Base, BasePath, Lang, Dir string
		Statuses                          []securityReportOption
		Labels                            map[string]string
	}{rows, r.URL.Query().Get("status"), base, requestPathPrefix(r), language, direction, statusOptions, labels}
	if err := securityReportListTemplate.Execute(w, data); err != nil {
		serverAuthError(w, r, http.StatusInternalServerError, "auth.pages.security_render_failed")
	}
}

func (s *SecurityReportService) decryptReportBody(ctx context.Context, record store.SecurityReportRecord) ([]byte, error) {
	if record.BodyAlg == "pgp" {
		if s.projectKeypair == nil {
			return nil, errors.New("project OpenPGP key manager is unavailable")
		}
		return s.projectKeypair.Decrypt(record.BodyEnc)
	}
	if record.BodyAlg != "aes-256-gcm" {
		return nil, errors.New("security report uses an unsupported encryption algorithm")
	}
	return s.decrypt(record.BodyEnc)
}

type securityReportListItem struct {
	TrackingID string
	Severity   string
	Status     string
	Component  string
	Summary    string
	CreatedAt  string
}

type securityReportOption struct{ Value, Label string }

var securityReportListTemplate = template.Must(template.New("security-report-list").Parse(`<!doctype html><html lang="{{.Lang}}" dir="{{.Dir}}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{{index .Labels "title"}}</title><link rel="stylesheet" href="{{.BasePath}}/static/css/style.css"></head><body><a class="skip-link" href="#main-content">{{index .Labels "skip"}}</a><main id="main-content" class="container container-md"><h1>{{index .Labels "title"}}</h1><form method="get"><label>{{index .Labels "status"}} <select name="status"><option value="">{{index .Labels "all"}}</option>{{range .Statuses}}<option value="{{.Value}}" {{if eq .Value $.Status}}selected{{end}}>{{.Label}}</option>{{end}}</select></label><button type="submit">{{index .Labels "filter"}}</button></form><table><thead><tr><th>{{index .Labels "tracking"}}</th><th>{{index .Labels "summary"}}</th><th>{{index .Labels "severity"}}</th><th>{{index .Labels "state"}}</th><th>{{index .Labels "component"}}</th><th>{{index .Labels "received"}}</th></tr></thead><tbody>{{range .Rows}}<tr><td><a href="{{$.Base}}/{{.TrackingID}}">{{.TrackingID}}</a></td><td>{{.Summary}}</td><td>{{.Severity}}</td><td>{{.Status}}</td><td>{{.Component}}</td><td><time>{{.CreatedAt}}</time></td></tr>{{else}}<tr><td colspan="6">{{index $.Labels "empty"}}</td></tr>{{end}}</tbody></table></main></body></html>`))

// AdminReportHandler serves report details and the authenticated triage update form.
func (s *SecurityReportService) AdminReportHandler(w http.ResponseWriter, r *http.Request) {
	adminName, adminSessionID, ok := s.requireSecurityAdmin(w, r)
	if !ok {
		return
	}
	trackingID := r.PathValue("tracking_id")
	if trackingID == "" {
		trackingID = strings.TrimPrefix(r.URL.Path, "/")
		trackingID = trackingID[strings.LastIndex(trackingID, "/")+1:]
	}
	switch r.Method {
	case http.MethodGet:
		view, err := s.DecryptedAdminReport(r.Context(), trackingID)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		if s.securityLog != nil {
			s.securityLog("security.report_viewed", map[string]any{"tracking_id": trackingID, "admin": adminName})
		}
		w.Header().Set("Cache-Control", "private, no-store")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		csrfToken := s.adminCSRFToken(adminSessionID)
		requestOrigin, _ := url.Parse(BuildURL(r, "/"))
		http.SetCookie(w, &http.Cookie{Name: "csrf_token", Value: csrfToken, Path: prefixPagePath(requestPathPrefix(r), "/"), Secure: requestOrigin != nil && requestOrigin.Scheme == "https", SameSite: http.SameSiteStrictMode, HttpOnly: false})
		view["csrfToken"] = csrfToken
		record := view["record"].(*store.SecurityReportRecord)
		statuses := []string{"received", "triaged", "confirmed", "patching", "disclosed", "wont_fix"}
		severities := []string{"critical", "high", "medium", "low", "informational"}
		statusOptions := make([]securityReportOption, 0, len(statuses))
		for _, value := range statuses {
			statusOptions = append(statusOptions, securityReportOption{Value: value, Label: securityStatusLabel(r, value)})
		}
		severityOptions := make([]securityReportOption, 0, len(severities))
		for _, value := range severities {
			severityOptions = append(severityOptions, securityReportOption{Value: value, Label: securitySeverityLabel(r, value)})
		}
		language, direction := requestLanguage(r)
		view["statuses"], view["severities"] = statusOptions, severityOptions
		view["lang"], view["dir"], view["basePath"] = language, direction, requestPathPrefix(r)
		view["labels"] = map[string]string{
			"title": serverAuthText(r, "auth.pages.security_reports_title"), "skip": serverAuthText(r, "nav.skip_to_content"),
			"researcher": serverAuthText(r, "auth.pages.security_researcher"), "details": serverAuthText(r, "auth.pages.security_vulnerability_details"),
			"status": serverAuthText(r, "auth.pages.security_status"), "severity": serverAuthText(r, "auth.pages.security_severity"),
			"comment": serverAuthText(r, "auth.pages.security_researcher_comment"), "date": serverAuthText(r, "auth.pages.security_disclosure_date"),
			"save": serverAuthText(r, "auth.pages.security_save_update"),
		}
		view["currentStatus"] = record.Status
		view["currentSeverity"] = record.Severity
		view["currentComment"] = record.ResearcherComment
		if record.DisclosureDate != nil {
			view["currentDisclosureDate"] = record.DisclosureDate.UTC().Format("2006-01-02")
		}
		if err := securityReportDetailTemplate.Execute(w, view); err != nil {
			serverAuthError(w, r, http.StatusInternalServerError, "auth.pages.security_render_failed")
		}
	case http.MethodPost:
		r.Body = http.MaxBytesReader(w, r.Body, 32*1024)
		if err := r.ParseForm(); err != nil {
			serverAuthError(w, r, http.StatusBadRequest, "auth.pages.security_update_invalid")
			return
		}
		if !isSameOriginRequest(r) {
			s.logCSRFFailure(r, "origin_mismatch")
			serverAuthError(w, r, http.StatusForbidden, "auth.pages.security_csrf_failed")
			return
		}
		cookie, err := r.Cookie("csrf_token")
		if err != nil || !validAdminCSRFToken(adminSessionID, cookie.Value, r.Form.Get("csrf_token"), s.adminCSRFToken(adminSessionID)) {
			s.logCSRFFailure(r, "token_mismatch")
			serverAuthError(w, r, http.StatusForbidden, "auth.pages.security_csrf_failed")
			return
		}
		var disclosureDate *time.Time
		if raw := strings.TrimSpace(r.FormValue("disclosure_date")); raw != "" {
			parsed, err := time.Parse("2006-01-02", raw)
			if err != nil {
				serverAuthError(w, r, http.StatusBadRequest, "auth.pages.security_date_invalid")
				return
			}
			parsed = parsed.UTC()
			disclosureDate = &parsed
		}
		old, _ := s.store.GetSecurityReport(r.Context(), trackingID)
		if old == nil {
			http.NotFound(w, r)
			return
		}
		if err := s.UpdateStatus(r.Context(), trackingID, r.FormValue("status"), r.FormValue("severity"), r.FormValue("researcher_comment"), disclosureDate, time.Now()); err != nil {
			serverAuthError(w, r, http.StatusBadRequest, "auth.pages.security_update_invalid")
			return
		}
		if s.securityLog != nil {
			s.securityLog("security.report_updated", map[string]any{"tracking_id": trackingID, "old_status": old.Status, "new_status": strings.ToLower(strings.TrimSpace(r.FormValue("status"))), "admin": adminName})
		}
		http.Redirect(w, r, r.URL.Path, http.StatusSeeOther)
	default:
		w.Header().Set("Allow", "GET, POST")
		serverAuthError(w, r, http.StatusMethodNotAllowed, "auth.pages.security_method_not_allowed")
	}
}

var securityReportDetailTemplate = template.Must(template.New("security-report-detail").Parse(`<!doctype html><html lang="{{.lang}}" dir="{{.dir}}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{{index .labels "title"}}</title><link rel="stylesheet" href="{{.basePath}}/static/css/style.css"></head><body><a class="skip-link" href="#main-content">{{index .labels "skip"}}</a><main id="main-content" class="container container-md"><h1>{{index .labels "title"}} {{.record.TrackingID}}</h1><h2>{{index .labels "researcher"}}</h2><pre>{{.researcher}}</pre><h2>{{index .labels "details"}}</h2><pre>{{.report}}</pre><form method="post"><input type="hidden" name="csrf_token" value="{{.csrfToken}}"><label>{{index .labels "status"}} <select name="status">{{range .statuses}}<option value="{{.Value}}" {{if eq .Value $.currentStatus}}selected{{end}}>{{.Label}}</option>{{end}}</select></label><label>{{index .labels "severity"}} <select name="severity">{{range .severities}}<option value="{{.Value}}" {{if eq .Value $.currentSeverity}}selected{{end}}>{{.Label}}</option>{{end}}</select></label><label>{{index .labels "comment"}} <textarea name="researcher_comment" maxlength="2000">{{.currentComment}}</textarea></label><label>{{index .labels "date"}} <input type="date" name="disclosure_date" value="{{.currentDisclosureDate}}"></label><button type="submit">{{index .labels "save"}}</button></form></main></body></html>`))

func (s *SecurityReportService) requireSecurityAdmin(w http.ResponseWriter, r *http.Request) (string, string, bool) {
	cookie, err := r.Cookie("admin_session")
	if err != nil {
		serverAuthError(w, r, http.StatusUnauthorized, "auth.pages.security_authentication_required")
		return "", "", false
	}
	session, err := s.store.GetAdminSession(r.Context(), cookie.Value)
	if err != nil || session == nil {
		serverAuthError(w, r, http.StatusUnauthorized, "auth.pages.security_authentication_required")
		return "", "", false
	}
	if err := s.store.UpdateAdminSessionActivity(r.Context(), session.ID); err != nil {
		serverAuthError(w, r, http.StatusUnauthorized, "auth.pages.security_authentication_required")
		return "", "", false
	}
	username, err := s.store.GetAdminUsername(r.Context(), session.AdminID)
	if err != nil || username == "" {
		serverAuthError(w, r, http.StatusUnauthorized, "auth.pages.security_authentication_required")
		return "", "", false
	}
	return username, session.ID, true
}
