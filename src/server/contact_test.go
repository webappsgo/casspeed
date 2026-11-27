package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/casapps/casspeed/src/config"
	"github.com/casapps/casspeed/src/server/store"
)

func newTestContactHandler(t *testing.T) *ContactHandler {
	t.Helper()
	cfg := config.Default()
	cfg.Server.Pages.Contact.Antispam.MinFillSeconds = 0
	cfg.Server.Pages.Contact.Antispam.ReviewMinSeconds = 0
	handler, err := NewContactHandler(cfg)
	if err != nil {
		t.Fatal(err)
	}
	database, err := store.NewSQLiteStore(filepath.Join(t.TempDir(), "contact.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	handler.SetCaptchaStore(database)
	t.Cleanup(func() { _ = database.Close() })
	return handler
}

func TestContactChooserAndTypeForms(t *testing.T) {
	handler := newTestContactHandler(t)
	chooser := httptest.NewRecorder()
	handler.ServeHTTP(chooser, httptest.NewRequest(http.MethodGet, "/server/contact", nil))
	if chooser.Code != http.StatusOK || !strings.Contains(chooser.Body.String(), "Make a privacy request") || strings.Contains(chooser.Body.String(), "name=\"email\"") {
		t.Fatalf("chooser did not render without fields: %d %s", chooser.Code, chooser.Body.String())
	}
	if chooser.Header().Get("X-Robots-Tag") != "noindex, nofollow" || !strings.Contains(chooser.Body.String(), `name="robots" content="noindex,nofollow"`) {
		t.Fatal("contact chooser is missing noindex controls")
	}
	mainStart, mainEnd := strings.Index(chooser.Body.String(), "<main"), strings.Index(chooser.Body.String(), "</main>")
	if mainStart < 0 || mainEnd < mainStart || strings.Contains(chooser.Body.String()[mainStart:mainEnd], "<input") {
		t.Fatal("chooser content should not contain form inputs")
	}
	for _, test := range []struct {
		kind      string
		want      []string
		forbidden []string
	}{
		{kind: "abuse", want: []string{"name", "email", "reported_url", "reason", "subject", "message", "captcha_answer", "captcha_id"}, forbidden: []string{"copyrighted_work", "good_faith", "accuracy", "signature", "request_kind"}},
		{kind: "dmca", want: []string{"name", "email", "reported_url", "copyrighted_work", "good_faith", "accuracy", "signature", "subject", "message", "captcha_answer", "captcha_id"}, forbidden: []string{"reason", "request_kind"}},
		{kind: "privacy", want: []string{"name", "email", "request_kind", "subject", "message", "captcha_answer", "captcha_id"}, forbidden: []string{"reported_url", "reason", "copyrighted_work", "good_faith", "accuracy", "signature"}},
	} {
		t.Run(test.kind, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/server/contact?type="+test.kind, nil))
			body := recorder.Body.String()
			if recorder.Code != http.StatusOK {
				t.Fatalf("type form mismatch: %d %s", recorder.Code, body)
			}
			for _, field := range test.want {
				if !strings.Contains(body, `name="`+field+`"`) {
					t.Errorf("%s form missing field %s", test.kind, field)
				}
			}
			for _, field := range test.forbidden {
				if strings.Contains(body, `name="`+field+`"`) {
					t.Errorf("%s form contains unrelated field %s", test.kind, field)
				}
			}
			for _, field := range test.want {
				if field == "captcha_id" {
					continue
				}
				if field == "type" || field == "form_token" || field == "step" || field == "website" {
					continue
				}
				required := regexp.MustCompile(`name="` + regexp.QuoteMeta(field) + `"[^>]*required`)
				if !required.MatchString(body) {
					t.Errorf("required field %s is missing its required attribute", field)
				}
			}
			mainBodyStart, mainBodyEnd := strings.Index(body, "<main"), strings.Index(body, "</main>")
			if mainBodyStart < 0 || mainBodyEnd < mainBodyStart {
				t.Fatal("contact form is missing the main content region")
			}
			main := body[mainBodyStart:mainBodyEnd]
			names := regexp.MustCompile(`name="([^"]+)"`).FindAllStringSubmatch(main, -1)
			got := map[string]bool{}
			for _, match := range names {
				got[match[1]] = true
			}
			want := map[string]bool{"type": true, "form_token": true, "step": true, "csrf_token": true, "captcha_answer": true, "captcha_id": true, "website": true}
			for _, field := range test.want {
				want[field] = true
			}
			if len(got) != len(want) {
				t.Errorf("%s form field set = %v, want %v", test.kind, got, want)
			}
			for field := range want {
				if !got[field] {
					t.Errorf("%s form missing exact field %s", test.kind, field)
				}
			}
		})
	}
}

func TestContactAPIFormDescriptor(t *testing.T) {
	handler := newTestContactHandler(t)
	recorder := httptest.NewRecorder()
	handler.API(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/server/contact", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("descriptor status = %d: %s", recorder.Code, recorder.Body.String())
	}
	var response struct {
		OK   bool `json:"ok"`
		Data struct {
			Fields      []contactField `json:"fields"`
			Captcha     map[string]any `json:"captcha"`
			FormToken   string         `json:"form_token"`
			Types       []string       `json:"types"`
			SecurityURL string         `json:"security_url"`
			AbuseEmail  string         `json:"abuse_email"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if !response.OK || len(response.Data.Fields) == 0 || response.Data.Captcha["provider"] != "simple" || response.Data.FormToken == "" || len(response.Data.Types) != 3 || response.Data.SecurityURL == "" {
		t.Fatalf("invalid descriptor: %#v", response)
	}
	selected := httptest.NewRecorder()
	handler.API(selected, httptest.NewRequest(http.MethodGet, "/api/v1/server/contact?type=privacy", nil))
	var selectedResponse struct {
		Data struct {
			Fields []contactField `json:"fields"`
		} `json:"data"`
	}
	if err := json.Unmarshal(selected.Body.Bytes(), &selectedResponse); err != nil {
		t.Fatal(err)
	}
	fieldNames := map[string]bool{}
	for _, field := range selectedResponse.Data.Fields {
		fieldNames[field.Name] = true
	}
	if !fieldNames["request_kind"] || fieldNames["reported_url"] || fieldNames["copyrighted_work"] {
		t.Fatalf("selected API type has unrelated fields: %v", fieldNames)
	}
}

func TestContactFormAndCaptchaTokensAreSingleUse(t *testing.T) {
	handler := newTestContactHandler(t)
	now := time.Now()
	formToken, err := handler.newFormToken(now)
	if err != nil {
		t.Fatal(err)
	}
	if !handler.consumeFormToken(formToken, now.Add(time.Second)) || handler.consumeFormToken(formToken, now.Add(time.Second)) {
		t.Fatal("form token did not enforce one-use semantics")
	}
	captcha, err := handler.newCaptcha()
	if err != nil {
		t.Fatal(err)
	}
	answer := answerForCaptcha(t, captcha.Question)
	if !handler.consumeCaptcha(captcha.ID, answer, time.Now()) || handler.consumeCaptcha(captcha.ID, answer, time.Now()) {
		t.Fatal("captcha challenge did not enforce one-use semantics")
	}
}

func TestContactCaptchaProviderDescriptorAndVerification(t *testing.T) {
	handler := newTestContactHandler(t)
	handler.captchaProvider = "recaptcha"
	handler.captchaSiteKey = "public-site-key"
	handler.captchaSecretKey = "private-secret"
	response := httptest.NewRecorder()
	handler.API(response, httptest.NewRequest(http.MethodGet, "/api/v1/server/contact?type=privacy", nil))
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"provider":"recaptcha"`) || !strings.Contains(response.Body.String(), `"site_key":"public-site-key"`) || !strings.Contains(response.Body.String(), `"fallback"`) || strings.Contains(response.Body.String(), "private-secret") {
		t.Fatalf("unsafe or incomplete provider descriptor: %d %s", response.Code, response.Body.String())
	}
	page := httptest.NewRecorder()
	handler.ServeHTTP(page, httptest.NewRequest(http.MethodGet, "/server/contact?type=privacy", nil))
	if page.Code != http.StatusOK || !strings.Contains(page.Body.String(), `class="g-recaptcha"`) || !strings.Contains(page.Body.String(), "www.google.com/recaptcha/api.js") || !strings.Contains(page.Body.String(), "<noscript>") || !strings.Contains(page.Body.String(), `name="captcha_answer"`) {
		t.Fatalf("provider form lacks widget or no-JavaScript fallback: %d %s", page.Code, page.Body.String())
	}

	captcha, err := handler.newCaptcha()
	if err != nil {
		t.Fatal(err)
	}
	answer := answerForCaptcha(t, captcha.Question)
	transport := captchaRoundTripper(func(request *http.Request) (*http.Response, error) {
		body, err := io.ReadAll(request.Body)
		if err != nil {
			return nil, err
		}
		form, err := url.ParseQuery(string(body))
		if err != nil || form.Get("secret") != "private-secret" || form.Get("response") != "provider-proof" {
			return nil, errors.New("provider verification request was malformed")
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"success":true}`)), Header: make(http.Header)}, nil
	})
	handler.captchaHTTPClient = &http.Client{Transport: transport}
	request := httptest.NewRequest(http.MethodPost, "https://example.test/server/contact", nil)
	valid, unavailable, limited, _ := handler.verifyCaptchaSubmission(request, map[string]string{"captcha_response": "provider-proof", "captcha_id": captcha.ID, "captcha_answer": answer}, time.Now())
	if !valid || unavailable || limited {
		t.Fatalf("valid provider proof failed: valid=%t unavailable=%t limited=%t", valid, unavailable, limited)
	}
	if handler.consumeCaptcha(captcha.ID, answer, time.Now()) {
		t.Fatal("fallback challenge remained reusable after provider proof")
	}
}

func TestSimpleCaptchaChallengePersistsAndExpires(t *testing.T) {
	handler := newTestContactHandler(t)
	id := "0123456789abcdef0123456789abcdef"
	answer := contactHash("42")
	if err := handler.captchaStore.CreateCaptchaChallenge(t.Context(), id, answer, time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if handler.consumeCaptcha(id, "42", time.Now()) {
		t.Fatal("expired persistent challenge was accepted")
	}
	if handler.consumeCaptcha(id, "42", time.Now()) {
		t.Fatal("expired challenge was not consumed")
	}
}

func TestContactCaptchaProviderFailsClosedAndTorUsesSimple(t *testing.T) {
	handler := newTestContactHandler(t)
	handler.captchaProvider = "hcaptcha"
	handler.captchaSecretKey = "secret"
	challenge, err := handler.newCaptcha()
	if err != nil {
		t.Fatal(err)
	}
	answer := answerForCaptcha(t, challenge.Question)
	handler.captchaHTTPClient = &http.Client{Transport: captchaRoundTripper(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("provider unavailable")
	})}
	request := httptest.NewRequest(http.MethodPost, "https://example.test/server/contact", nil)
	valid, unavailable, _, _ := handler.verifyCaptchaSubmission(request, map[string]string{"captcha_response": "unverified", "captcha_id": challenge.ID, "captcha_answer": answer}, time.Now())
	if valid || !unavailable {
		t.Fatalf("provider outage did not fail closed: valid=%t unavailable=%t", valid, unavailable)
	}
	if handler.consumeCaptcha(challenge.ID, answer, time.Now()) {
		t.Fatal("failed provider proof allowed fallback reuse")
	}
	request.Host = "service.example.onion"
	if got := handler.SelectedCaptchaProvider(request); got != "simple" {
		t.Fatalf("Tor provider = %q, want simple", got)
	}
	request.Host = "service.example.i2p"
	if got := handler.SelectedCaptchaProvider(request); got != "simple" {
		t.Fatalf("I2P provider = %q, want simple", got)
	}
	request.Host = "service.example.onion"
	_, unavailable, _, _ = handler.verifyCaptchaSubmission(request, map[string]string{"captcha_response": "unverified"}, time.Now())
	if unavailable {
		t.Fatal("Tor request attempted an external CAPTCHA provider")
	}
}

func TestContactCaptchaMissingProviderKeysFallsBackToSimple(t *testing.T) {
	cfg := config.Default()
	cfg.Server.Pages.Contact.Captcha = "hcaptcha"
	cfg.Server.Pages.Contact.CaptchaSiteKey = "site-key"
	cfg.Server.Pages.Contact.CaptchaSecretKey = ""
	handler, err := NewContactHandler(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if handler.captchaProvider != "simple" {
		t.Fatalf("provider with missing secret key = %q, want simple", handler.captchaProvider)
	}
}

type captchaRoundTripper func(*http.Request) (*http.Response, error)

func (roundTrip captchaRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	return roundTrip(request)
}

func TestContactRejectsDisabledAndWrongMethods(t *testing.T) {
	handler := newTestContactHandler(t)
	handler.config.Server.Pages.Contact.Enabled = false
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/server/contact", nil))
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("disabled contact status = %d", recorder.Code)
	}
	handler.config.Server.Pages.Contact.Enabled = true
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPut, "/server/contact", nil))
	if recorder.Code != http.StatusMethodNotAllowed || recorder.Header().Get("Allow") != "GET, POST" {
		t.Fatalf("unsupported method = %d, Allow=%q", recorder.Code, recorder.Header().Get("Allow"))
	}
}

func TestContactHTMLSubmissionRejectsOversizedDuplicateAndOffsiteForms(t *testing.T) {
	tests := []struct {
		name   string
		body   string
		status int
	}{
		{"oversized", strings.Repeat("x", 256*1024+1), http.StatusRequestEntityTooLarge},
		{"duplicate", "type=privacy&type=abuse", http.StatusBadRequest},
		{"offsite", "type=privacy&name=Sender&email=sender%40example.test&subject=Report&message=Please+help", http.StatusBadRequest},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			handler := newTestContactHandler(t)
			request := httptest.NewRequest(http.MethodPost, "http://casspeed.test/server/contact?type=privacy", strings.NewReader(test.body))
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			request.RemoteAddr = "192.0.2.73:12345"
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.status {
				t.Fatalf("HTML submission status = %d, want %d: %s", response.Code, test.status, response.Body.String())
			}
			if test.name != "oversized" && response.Header().Get("X-Robots-Tag") != "noindex, nofollow" {
				t.Errorf("rejected form omitted noindex header: %v", response.Header())
			}
		})
	}
}

func TestContactRejectsUnknownAndInvalidSubmissionFields(t *testing.T) {
	fields, ok := contactFields("privacy")
	if !ok {
		t.Fatal("privacy fields are unavailable")
	}
	if err := validateContactShape(map[string]string{"name": "A", "email": "a@example.test", "extra": "x"}, fields); err == nil {
		t.Fatal("unknown field was accepted")
	}
	if err := validateContactShape(map[string]string{"name": "A", "email": "a@example.test", "type": "privacy", "request_kind": "access", "subject": "S", "message": "M"}, fields); err != nil {
		t.Fatalf("valid privacy fields rejected: %v", err)
	}
	if err := validateContactShape(map[string]string{"name": "A", "email": "a@example.test,b@example.test", "type": "privacy", "request_kind": "access", "subject": "S", "message": "M"}, fields); err == nil {
		t.Fatal("multiple email addresses were accepted")
	}
	if err := validateContactShape(map[string]string{"name": "A", "email": "a@example.test", "type": "abuse", "subject": "S", "message": "M"}, mustContactFields(t, "abuse")); err == nil {
		t.Fatal("abuse report without Reported URL was accepted")
	}
	if err := validateContactShape(map[string]string{"name": "A", "email": "a@example.test", "type": "dmca", "reported_url": "https://example.test/server/about", "copyrighted_work": "Work", "accuracy": "true", "signature": "A", "subject": "S", "message": "M"}, mustContactFields(t, "dmca")); err == nil {
		t.Fatal("DMCA notice without good-faith statement was accepted")
	}
	for _, unknownType := range []string{"", "general", "support", "bug"} {
		if _, ok := contactFields(unknownType); ok {
			t.Errorf("unsupported type %q was accepted", unknownType)
		}
	}
	if err := validateContactShape(map[string]string{"name": "A", "email": "a@example.test", "type": "privacy", "request_kind": "access", "subject": "bad\r\nBcc: x@example.test", "message": "M"}, fields); err == nil {
		t.Fatal("CR/LF in subject was accepted")
	}
}

func mustContactFields(t *testing.T, typeName string) []contactField {
	t.Helper()
	fields, ok := contactFields(typeName)
	if !ok {
		t.Fatalf("contact fields unavailable for %s", typeName)
	}
	return fields
}

func TestContactRejectsOffsiteReportedURLAndMarkup(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "http://example.test/server/contact", nil)
	if err := validateContactContent(request, map[string]string{"reported_url": "https://attacker.test/server/about"}, nil, true); err == nil {
		t.Fatal("off-site reported URL was accepted")
	}
	if err := validateContactContent(request, map[string]string{"message": "<script>alert(1)</script>"}, nil, true); err == nil {
		t.Fatal("markup was accepted")
	}
	for _, markup := range []string{"<a href=\"https://example.test\">link</a>", "[url=https://example.test]link[/url]", "&lt;tag&gt;"} {
		if err := validateContactContent(request, map[string]string{"message": markup}, nil, true); err == nil {
			t.Errorf("markup %q was accepted", markup)
		}
	}
}

func TestContactContentRulesAndReportedURLRouting(t *testing.T) {
	cfg := config.Default()
	cfg.Server.FQDN = "example.test"
	cfg.Server.Pages.Contact.Antispam.MaxLinks = 2
	cfg.Server.Pages.Contact.Antispam.BlockedWords = []string{"forbidden phrase"}
	cfg.Server.Pages.Contact.Antispam.BlockedEmailDomains = []string{"blocked.test"}
	request := httptest.NewRequest(http.MethodPost, "http://node.test/server/contact", nil)
	fields, _ := contactFields("abuse")
	for _, typeName := range []string{"abuse", "dmca", "privacy"} {
		values := map[string]string{"type": typeName, "name": "Sender", "email": "sender@example.test", "subject": "Report", "message": "See https://example.test/server/about"}
		if typeName != "privacy" {
			values["reported_url"] = "https://example.test/server/about"
		}
		if err := validateContactContent(request, values, fields, true, cfg); err != nil {
			t.Errorf("same-site report link rejected for %s: %v", typeName, err)
		}
		values["message"] = "See https://attacker.test/page"
		if err := validateContactContent(request, values, fields, true, cfg); err == nil {
			t.Errorf("off-site content link accepted for %s", typeName)
		}
	}
	values := map[string]string{"type": "abuse", "name": "Sender", "email": "sender@example.test", "subject": "Report", "message": "body", "reported_url": "https://example.test/not-a-route"}
	if err := validateContactContent(request, values, fields, true, cfg); err == nil {
		t.Fatal("reported URL with no matching route was accepted")
	}
	values["reported_url"] = "https://example.test/server/about"
	values["message"] = "forbidden phrase"
	if err := validateContactContent(request, values, fields, true, cfg); err == nil {
		t.Fatal("blocked word was accepted")
	}
	values["message"] = "ordinary text"
	values["email"] = "sender@blocked.test"
	if err := validateContactContent(request, values, fields, true, cfg); err == nil {
		t.Fatal("blocked email domain was accepted")
	}
}

func TestContactOriginRequiresOwnOriginAndSameFetchSite(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "https://example.test/server/contact", nil)
	request.Header.Set("Origin", "https://example.test")
	if !sameContactOrigin(request) {
		t.Fatal("matching origin was rejected")
	}
	request.Header.Set("Sec-Fetch-Site", "cross-site")
	if sameContactOrigin(request) {
		t.Fatal("cross-site Sec-Fetch-Site was accepted")
	}
}

func TestContactTwoPhaseDeliveryAndHoneypotDrop(t *testing.T) {
	for _, honeypot := range []bool{false, true} {
		t.Run(strconv.FormatBool(honeypot), func(t *testing.T) {
			handler := newTestContactHandler(t)
			handler.config.Server.Pages.Contact.Antispam.Honeypot = true
			handler.config.Server.Contact.General.Email = "reports@example.test"
			deliveries := 0
			handler.SetDelivery(func(_, _, _, _, _ string) error { deliveries++; return nil })
			values := makePrivacySubmission(t, handler)
			if honeypot {
				values["website"] = "bot-filled"
			}
			stepOne := postContactAPI(handler, values)
			if stepOne.Code != http.StatusOK || deliveries != 0 || !strings.Contains(stepOne.Body.String(), `"review_token"`) {
				t.Fatalf("submit step must only review, status=%d deliveries=%d body=%s", stepOne.Code, deliveries, stepOne.Body.String())
			}
			var first struct {
				Data map[string]any `json:"data"`
			}
			if err := json.Unmarshal(stepOne.Body.Bytes(), &first); err != nil {
				t.Fatal(err)
			}
			values["step"] = "confirm"
			values["review_token"] = first.Data["review_token"].(string)
			values["form_token"] = first.Data["form_token"].(string)
			values["confirmed"] = "true"
			delete(values, "captcha_id")
			delete(values, "captcha_answer")
			stepTwo := postContactAPI(handler, values)
			if stepTwo.Code != http.StatusOK || !strings.Contains(stepTwo.Body.String(), `"accepted":true`) {
				t.Fatalf("confirm step failed: %d %s", stepTwo.Code, stepTwo.Body.String())
			}
			wantDeliveries := 1
			if honeypot {
				wantDeliveries = 0
			}
			if deliveries != wantDeliveries {
				t.Fatalf("deliveries = %d, want %d", deliveries, wantDeliveries)
			}
		})
	}
}

func TestContactHTMLReviewShowsConfirmationWithoutSensitiveFormTokens(t *testing.T) {
	handler := newTestContactHandler(t)
	values := map[string]string{
		"type": "privacy", "email": "sender@example.test", "subject": "Data request", "message": "Please export my data",
		"form_token": "form-secret", "captcha_id": "captcha-secret", "captcha_answer": "answer-secret",
		"csrf_token": "csrf-secret", "review_token": "old-token", "confirmed": "true",
	}
	request := httptest.NewRequest(http.MethodGet, "https://example.test/server/contact", nil)
	response := httptest.NewRecorder()
	handler.serveReview(response, request, values, "review-secret")
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "review-secret") || !strings.Contains(response.Body.String(), "sender@example.test") {
		t.Fatalf("review page returned %d: %s", response.Code, response.Body.String())
	}
	for _, secret := range []string{"captcha-secret", "answer-secret", "csrf-secret", "old-token"} {
		if strings.Contains(response.Body.String(), secret) {
			t.Errorf("review page exposed transient token %q", secret)
		}
	}
	if !strings.Contains(response.Body.String(), `name="form_token" value="form-secret"`) {
		t.Fatal("review form lost the single-use fill-time token required by the contact flow")
	}
	if !strings.Contains(response.Body.String(), `name="step" value="confirm"`) || !strings.Contains(response.Body.String(), `name="step" value="edit"`) {
		t.Fatal("review page did not offer separate confirm and edit actions")
	}
	if contactReviewType(map[string]string{"security_id": "report-token"}) != "security" {
		t.Fatal("security review was not assigned the security type")
	}
}

func TestContactRateLimitCountsConfirmedSubmissions(t *testing.T) {
	handler := newTestContactHandler(t)
	handler.config.Server.Pages.Contact.Antispam.PerIP = 5
	handler.config.Server.Pages.Contact.Antispam.PerEmail = 100
	handler.config.Server.Pages.Contact.Antispam.Global = 100
	handler.config.Server.Contact.General.Email = "reports@example.test"
	handler.SetDelivery(func(_, _, _, _, _ string) error { return nil })
	for i := 0; i < 5; i++ {
		values := makePrivacySubmission(t, handler)
		values["email"] = "sender" + strconv.Itoa(i) + "@example.test"
		if response := completeContactAPI(handler, values); response.Code != http.StatusOK {
			t.Fatalf("accepted submission %d failed: %d %s", i+1, response.Code, response.Body.String())
		}
	}
	values := makePrivacySubmission(t, handler)
	values["email"] = "sixth@example.test"
	response := postContactAPI(handler, values)
	if response.Code != http.StatusTooManyRequests || response.Header().Get("Retry-After") == "" {
		t.Fatalf("sixth submission = %d, Retry-After=%q", response.Code, response.Header().Get("Retry-After"))
	}
}

func TestContactDuplicateIsSilentlyDropped(t *testing.T) {
	handler := newTestContactHandler(t)
	handler.config.Server.Pages.Contact.Antispam.DuplicateWindowHours = 24
	handler.config.Server.Contact.General.Email = "reports@example.test"
	deliveries := 0
	handler.SetDelivery(func(_, _, _, _, _ string) error { deliveries++; return nil })
	for i := 0; i < 2; i++ {
		values := makePrivacySubmission(t, handler)
		response := completeContactAPI(handler, values)
		if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"accepted":true`) {
			t.Fatalf("duplicate response %d: %d %s", i, response.Code, response.Body.String())
		}
	}
	if deliveries != 1 {
		t.Fatalf("duplicate notification deliveries = %d, want 1", deliveries)
	}
}

func TestContactFormTokenAgeForgeryAndExpiry(t *testing.T) {
	handler := newTestContactHandler(t)
	handler.config.Server.Pages.Contact.Antispam.MinFillSeconds = 3
	handler.config.Server.Pages.Contact.Antispam.MaxAgeSeconds = 10
	now := time.Now()
	tooYoung, err := handler.newFormToken(now)
	if err != nil {
		t.Fatal(err)
	}
	if handler.consumeFormTokenFailure(tooYoung, now) != "fill_time" {
		t.Fatal("too-young form token was accepted")
	}
	if handler.consumeFormTokenFailure("1.not-a-valid-token.deadbeef", now.Add(5*time.Second)) != "fill_time" {
		t.Fatal("forged form token was accepted")
	}
	expired, err := handler.newFormToken(now)
	if err != nil {
		t.Fatal(err)
	}
	if handler.consumeFormTokenFailure(expired, now.Add(11*time.Second)) != "fill_time" {
		t.Fatal("expired form token was accepted")
	}
}

func TestContactReviewRejectsChangedFieldsAndTooYoungToken(t *testing.T) {
	handler := newTestContactHandler(t)
	handler.config.Server.Pages.Contact.Antispam.ReviewMinSeconds = 3
	values := makePrivacySubmission(t, handler)
	now := time.Now()
	token, err := handler.newReviewToken(values, now)
	if err != nil {
		t.Fatal(err)
	}
	if handler.consumeReviewToken(token, values, now) {
		t.Fatal("too-young review token was accepted")
	}
	token, err = handler.newReviewToken(values, now)
	if err != nil {
		t.Fatal(err)
	}
	values["message"] = "changed"
	if handler.consumeReviewToken(token, values, now.Add(4*time.Second)) {
		t.Fatal("changed review fields were accepted")
	}
}

func TestContactConfirmRequiresExplicitCheckbox(t *testing.T) {
	handler := newTestContactHandler(t)
	handler.config.Server.Contact.General.Email = "reports@example.test"
	deliveries := 0
	handler.SetDelivery(func(_, _, _, _, _ string) error { deliveries++; return nil })
	values := makePrivacySubmission(t, handler)
	first := postContactAPI(handler, values)
	var payload struct {
		Data map[string]any `json:"data"`
	}
	if first.Code != http.StatusOK || json.Unmarshal(first.Body.Bytes(), &payload) != nil {
		t.Fatalf("submit step failed: %d %s", first.Code, first.Body.String())
	}
	values["step"] = "confirm"
	values["review_token"] = payload.Data["review_token"].(string)
	values["form_token"] = payload.Data["form_token"].(string)
	delete(values, "captcha_id")
	delete(values, "captcha_answer")
	response := postContactAPI(handler, values)
	if response.Code != http.StatusBadRequest || deliveries != 0 || !strings.Contains(response.Body.String(), `"field":"confirmed"`) {
		t.Fatalf("confirmation without checkbox was accepted: %d %s deliveries=%d", response.Code, response.Body.String(), deliveries)
	}
}

func TestContactOriginFailureAndStrikeBan(t *testing.T) {
	handler := newTestContactHandler(t)
	request := httptest.NewRequest(http.MethodPost, "http://example.test/server/contact", nil)
	if sameContactOrigin(request) {
		t.Fatal("request without Origin, Referer or Sec-Fetch-Site was accepted")
	}
	request.Header.Set("Origin", "https://attacker.test")
	if sameContactOrigin(request) {
		t.Fatal("mismatched Origin was accepted")
	}
	now := time.Now()
	for i := 0; i < 3; i++ {
		handler.recordStrike(request, now.Add(time.Duration(i)*time.Second))
	}
	if banned, retry := handler.checkBan(request, now.Add(4*time.Second)); !banned || retry <= 0 {
		t.Fatalf("third strike did not ban client: banned=%t retry=%s", banned, retry)
	}
}

func makePrivacySubmission(t *testing.T, handler *ContactHandler) map[string]string {
	t.Helper()
	now := time.Now()
	formToken, err := handler.newFormToken(now.Add(-time.Second))
	if err != nil {
		t.Fatal(err)
	}
	captcha, err := handler.newCaptcha()
	if err != nil {
		t.Fatal(err)
	}
	answer := answerForCaptcha(t, captcha.Question)
	return map[string]string{"type": "privacy", "name": "Sender", "email": "sender@example.test", "request_kind": "access", "subject": "Data access", "message": "Please provide my data", "form_token": formToken, "captcha_id": captcha.ID, "captcha_answer": answer, "website": ""}
}

func answerForCaptcha(t *testing.T, question string) string {
	t.Helper()
	var left, right int
	if _, err := fmt.Sscanf(question, "What is %d - %d?", &left, &right); err == nil {
		return strconv.Itoa(left - right)
	}
	if _, err := fmt.Sscanf(question, "What is %d + %d?", &left, &right); err == nil {
		return strconv.Itoa(left + right)
	}
	t.Fatalf("unexpected captcha question %q", question)
	return ""
}

func postContactAPI(handler *ContactHandler, values map[string]string) *httptest.ResponseRecorder {
	body, _ := json.Marshal(values)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/v1/server/contact", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	handler.API(recorder, request)
	return recorder
}

func completeContactAPI(handler *ContactHandler, values map[string]string) *httptest.ResponseRecorder {
	first := postContactAPI(handler, values)
	if first.Code != http.StatusOK {
		return first
	}
	var payload struct {
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal(first.Body.Bytes(), &payload); err != nil {
		return first
	}
	values["step"] = "confirm"
	values["review_token"] = payload.Data["review_token"].(string)
	values["form_token"] = payload.Data["form_token"].(string)
	values["confirmed"] = "true"
	delete(values, "captcha_id")
	delete(values, "captcha_answer")
	return postContactAPI(handler, values)
}
