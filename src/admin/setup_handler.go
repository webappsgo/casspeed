package admin

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"html/template"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/casapps/casspeed/src/server/model"
	"github.com/casapps/casspeed/src/theme"
	"golang.org/x/crypto/argon2"
)

// SetupTokenHandler handles the setup token submission
func (a *AdminHandler) SetupTokenHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, adminText(r, "error.method_not_allowed"), http.StatusMethodNotAllowed)
		return
	}

	// Check if setup is already complete
	if IsSetupComplete() {
		http.Redirect(w, r, a.adminRootPath(), http.StatusSeeOther)
		return
	}

	// Parse form
	if err := r.ParseForm(); err != nil {
		http.Error(w, adminText(r, "setup.error.invalid_form"), http.StatusBadRequest)
		return
	}

	token := r.FormValue("token")
	if token == "" {
		a.renderSetupTokenPage(w, r, adminText(r, "setup.error.token_required"))
		return
	}

	// Validate token
	if !ValidateSetupToken(token) {
		a.renderSetupTokenPage(w, r, adminText(r, "setup.error.token_invalid"))
		return
	}
	if err := IssueSetupSession(w, r); err != nil {
		http.Error(w, adminText(r, "setup.error.authorize"), http.StatusInternalServerError)
		return
	}

	// Token valid - redirect to setup wizard
	http.Redirect(w, r, a.adminRootPath()+"/setup", http.StatusSeeOther)
}

// SetupWizardHandler handles the setup wizard page
func (a *AdminHandler) SetupWizardHandler(w http.ResponseWriter, r *http.Request) {
	// Check if setup is already complete
	if IsSetupComplete() {
		http.Redirect(w, r, a.adminRootPath(), http.StatusSeeOther)
		return
	}
	if !validSetupSession(r) {
		a.renderSetupTokenPage(w, r, "")
		return
	}

	themeVal := theme.DetectTheme(r)

	catalog, language := adminLocale(r)
	data := map[string]interface{}{
		"Theme":     themeVal,
		"ThemeCSS":  theme.GetThemeCSS(themeVal),
		"Step":      1,
		"Lang":      language,
		"Direction": catalog.Meta.Direction,
		"AdminRoot": a.adminRootPath(),
		"T":         func(key string) string { return catalog.T("admin.legacy."+key, nil) },
	}

	a.renderSetupWizard(w, data)
}

// SetupCompleteHandler handles the final step of setup wizard
func (a *AdminHandler) SetupCompleteHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, adminText(r, "error.method_not_allowed"), http.StatusMethodNotAllowed)
		return
	}

	// Check if setup is already complete
	if IsSetupComplete() {
		http.Error(w, adminText(r, "setup.error.completed"), http.StatusBadRequest)
		return
	}
	if !validSetupSession(r) {
		http.Error(w, adminText(r, "setup.error.authorization_required"), http.StatusUnauthorized)
		return
	}

	// Parse JSON body
	var setupData SetupWizardData
	if err := json.NewDecoder(r.Body).Decode(&setupData); err != nil {
		http.Error(w, adminText(r, "setup.error.invalid_request"), http.StatusBadRequest)
		return
	}

	// Validate data
	if err := ValidateSetupData(&setupData); err != nil {
		http.Error(w, setupValidationMessage(r, err), http.StatusBadRequest)
		return
	}

	// Generate API token if not provided
	if setupData.AdminAPIToken == "" {
		token, err := generateAPIToken()
		if err != nil {
			http.Error(w, adminText(r, "setup.error.token_generation"), http.StatusInternalServerError)
			return
		}
		setupData.AdminAPIToken = token
	}

	// Hash admin password
	passwordHash, err := hashPassword(setupData.AdminPassword)
	if err != nil {
		http.Error(w, adminText(r, "setup.error.password_hash"), http.StatusInternalServerError)
		return
	}

	if !validAdminTokenFormat(setupData.AdminAPIToken) {
		http.Error(w, adminText(r, "setup.error.token_format"), http.StatusBadRequest)
		return
	}
	tokenHash := sha256.Sum256([]byte(setupData.AdminAPIToken))

	// Create admin account in database
	ctx := r.Context()
	adminAccount := &model.Admin{
		Username:     setupData.AdminUsername,
		Password:     passwordHash,
		Email:        "", // Optional, can be set later
		Role:         "primary",
		Enabled:      true,
		APITokenHash: hex.EncodeToString(tokenHash[:]),
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	// Save admin to database
	if err := a.store.CreateAdmin(ctx, adminAccount); err != nil {
		http.Error(w, adminText(r, "setup.error.create_admin"), http.StatusInternalServerError)
		return
	}

	setupData.CompletedAt = time.Now()
	setupData.CompletedByIP = getClientIP(r)

	// Save setup completion to database
	if err := a.store.SetSetupComplete(ctx, true); err != nil {
		http.Error(w, adminText(r, "setup.error.save_status"), http.StatusInternalServerError)
		return
	}
	consumeSetupSession(r)
	MarkSetupComplete()
	http.SetCookie(w, &http.Cookie{Name: "casspeed_setup", Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteStrictMode})

	// Config saved via server.yml on first run - admin modifies via /admin/server/settings
	// This requires config package access

	// Return success with API token
	response := map[string]interface{}{
		"success":   true,
		"api_token": setupData.AdminAPIToken,
		"message":   adminText(r, "setup.completed_successfully"),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// renderSetupTokenPage renders the setup token entry page
func (a *AdminHandler) renderSetupTokenPage(w http.ResponseWriter, r *http.Request, errorMsg string) {
	themeVal := theme.DetectTheme(r)

	tmpl := `<!DOCTYPE html>
<html lang="{{.Lang}}" dir="{{.Direction}}">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>{{t "setup.title"}} - casspeed</title>
	<style>
		{{.ThemeCSS}}
		body {
			font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
			display: flex;
			justify-content: center;
			align-items: center;
			min-height: 100vh;
			margin: 0;
			padding: 20px;
		}
		.setup-card {
			background: var(--hover-color);
			border: 1px solid var(--border-color);
			border-radius: 8px;
			padding: 40px;
			max-width: 400px;
			width: 100%;
			box-shadow: 0 4px 6px rgba(0,0,0,0.1);
		}
		h1 {
			margin: 0 0 10px 0;
			font-size: 24px;
		}
		.subtitle {
			color: var(--text-color);
			opacity: 0.7;
			margin: 0 0 30px 0;
		}
		.error {
			background: #fee;
			color: #c33;
			padding: 10px;
			border-radius: 4px;
			margin-bottom: 20px;
		}
		input[type="text"] {
			width: 100%;
			padding: 12px;
			border: 1px solid var(--border-color);
			border-radius: 4px;
			font-size: 14px;
			background: var(--bg-color);
			color: var(--text-color);
			box-sizing: border-box;
		}
		button {
			width: 100%;
			padding: 12px;
			background: #0066cc;
			color: white;
			border: none;
			border-radius: 4px;
			font-size: 16px;
			cursor: pointer;
			margin-top: 20px;
		}
		button:hover {
			background: #0052a3;
		}
		.version {
			text-align: center;
			margin-top: 30px;
			font-size: 12px;
			opacity: 0.5;
		}
	</style>
</head>
<body>
	<div class="setup-card">
		<h1>casspeed {{t "setup.title"}}</h1>
		<p class="subtitle">{{t "setup.token_lead"}}</p>
		{{if .Error}}
		<div class="error">{{.Error}}</div>
		{{end}}
		<form method="POST" action="{{.AdminRoot}}/setup/token">
			<input type="text" name="token" placeholder="{{t "setup.token_label"}}" required autofocus>
			<button type="submit">{{t "setup.continue"}}</button>
		</form>
		<div class="version">v1.0.0</div>
	</div>
</body>
</html>`

	catalog, language := adminLocale(r)
	t, err := template.New("setup").Funcs(template.FuncMap{"t": func(key string) string { return catalog.T("admin.legacy."+key, nil) }}).Parse(tmpl)
	if err != nil {
		http.Error(w, adminText(r, "setup.error.template"), http.StatusInternalServerError)
		return
	}

	data := map[string]interface{}{
		"ThemeCSS":  theme.GetThemeCSS(themeVal),
		"Error":     errorMsg,
		"Lang":      language,
		"Direction": catalog.Meta.Direction,
		"AdminRoot": a.adminRootPath(),
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := t.Execute(w, data); err != nil {
		return
	}
}

// renderSetupWizard renders the setup wizard page
func (a *AdminHandler) renderSetupWizard(w http.ResponseWriter, data map[string]interface{}) {
	themeCSS := ""
	if css, ok := data["ThemeCSS"].(string); ok {
		themeCSS = css
	}

	tmpl := `<!DOCTYPE html>
<html lang="{{.Lang}}" dir="{{.Direction}}">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>{{t "setup.wizard_title"}} - casspeed</title>
	<style>
		` + themeCSS + `
		* { box-sizing: border-box; }
		body {
			font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
			margin: 0;
			padding: 20px;
			min-height: 100vh;
			display: flex;
			justify-content: center;
			align-items: flex-start;
		}
		.wizard-container {
			max-width: 600px;
			width: 100%;
			margin-top: 40px;
		}
		.wizard-header {
			text-align: center;
			margin-bottom: 30px;
		}
		.wizard-header h1 { margin: 0 0 10px; font-size: 28px; }
		.wizard-header p { margin: 0; opacity: 0.7; }
		.wizard-steps {
			display: flex;
			justify-content: space-between;
			margin-bottom: 30px;
			padding: 0 20px;
		}
		.step {
			display: flex;
			flex-direction: column;
			align-items: center;
			flex: 1;
		}
		.step-number {
			width: 36px;
			height: 36px;
			border-radius: 50%;
			background: var(--border-color, #444);
			display: flex;
			align-items: center;
			justify-content: center;
			font-weight: bold;
			margin-bottom: 8px;
		}
		.step.active .step-number {
			background: #0066cc;
			color: white;
		}
		.step.completed .step-number {
			background: #28a745;
			color: white;
		}
		.step-label { font-size: 12px; opacity: 0.7; }
		.wizard-card {
			background: var(--hover-color, #1e1e1e);
			border: 1px solid var(--border-color, #333);
			border-radius: 8px;
			padding: 30px;
		}
		.form-group { margin-bottom: 20px; }
		.form-group label {
			display: block;
			margin-bottom: 8px;
			font-weight: 500;
		}
		.form-group input, .form-group select {
			width: 100%;
			padding: 12px;
			border: 1px solid var(--border-color, #333);
			border-radius: 4px;
			background: var(--bg-color, #121212);
			color: var(--text-color, #fff);
			font-size: 14px;
		}
		.form-group input:focus, .form-group select:focus {
			outline: none;
			border-color: #0066cc;
		}
		.form-hint {
			font-size: 12px;
			opacity: 0.7;
			margin-top: 4px;
		}
		.checkbox-group {
			display: flex;
			align-items: center;
			gap: 10px;
		}
		.checkbox-group input[type="checkbox"] {
			width: auto;
		}
		.btn-group {
			display: flex;
			gap: 10px;
			margin-top: 30px;
		}
		.btn {
			flex: 1;
			padding: 12px 24px;
			border: none;
			border-radius: 4px;
			font-size: 16px;
			cursor: pointer;
		}
		.btn-primary {
			background: #0066cc;
			color: white;
		}
		.btn-primary:hover { background: #0052a3; }
		.btn-secondary {
			background: var(--border-color, #333);
			color: var(--text-color, #fff);
		}
		.api-token-display {
			background: var(--bg-color, #121212);
			border: 1px solid var(--border-color, #333);
			border-radius: 4px;
			padding: 16px;
			font-family: monospace;
			word-break: break-all;
			margin: 16px 0;
		}
		.warning {
			background: #ffc10733;
			border: 1px solid #ffc107;
			border-radius: 4px;
			padding: 12px;
			margin: 16px 0;
		}
		.success {
			background: #28a74533;
			border: 1px solid #28a745;
			border-radius: 4px;
			padding: 16px;
			text-align: center;
		}
		.hidden { display: none; }
	</style>
</head>
<body>
	<div class="wizard-container">
		<div class="wizard-header">
			<h1>casspeed {{t "setup.title"}}</h1>
			<p>{{t "setup.wizard_lead"}}</p>
		</div>

		<div class="wizard-steps">
			<div class="step active" id="step-indicator-1">
				<div class="step-number">1</div>
				<div class="step-label">{{t "setup.step_admin"}}</div>
			</div>
			<div class="step" id="step-indicator-2">
				<div class="step-number">2</div>
				<div class="step-label">{{t "setup.step_api_token"}}</div>
			</div>
			<div class="step" id="step-indicator-3">
				<div class="step-number">3</div>
				<div class="step-label">{{t "setup.step_server"}}</div>
			</div>
			<div class="step" id="step-indicator-4">
				<div class="step-number">4</div>
				<div class="step-label">{{t "setup.step_security"}}</div>
			</div>
			<div class="step" id="step-indicator-5">
				<div class="step-number">5</div>
				<div class="step-label">{{t "setup.step_complete"}}</div>
			</div>
		</div>

		<div class="wizard-card">
			<!-- Step 1: Admin Account -->
			<div id="step-1" class="wizard-step">
				<h2>{{t "setup.create_admin"}}</h2>
				<p>{{t "setup.admin_lead"}}</p>
				<div class="form-group">
					<label for="admin_username">{{t "setup.username"}}</label>
					<input type="text" id="admin_username" name="admin_username" value="administrator" required>
					<div class="form-hint">{{t "setup.username_hint"}}</div>
				</div>
				<div class="form-group">
					<label for="admin_password">{{t "setup.password"}}</label>
					<input type="password" id="admin_password" name="admin_password" required minlength="8">
					<div class="form-hint">{{t "setup.password_hint"}}</div>
				</div>
				<div class="form-group">
					<label for="admin_password_confirm">{{t "setup.confirm_password"}}</label>
					<input type="password" id="admin_password_confirm" name="admin_password_confirm" required>
				</div>
				<div class="btn-group">
					<button type="button" class="btn btn-primary" onclick="nextStep(1)">{{t "setup.next"}}</button>
				</div>
			</div>

			<!-- Step 2: API Token -->
			<div id="step-2" class="wizard-step hidden">
				<h2>{{t "setup.api_token"}}</h2>
				<p>{{t "setup.token_once"}}</p>
				<div class="api-token-display" id="api-token-display">
					<span id="api-token">{{t "setup.generating"}}</span>
				</div>
				<button type="button" class="btn btn-secondary" onclick="copyToken()">{{t "setup.copy_token"}}</button>
				<div class="warning">
					<strong>{{t "setup.important"}}</strong> {{t "setup.token_warning"}}
				</div>
				<div class="btn-group">
					<button type="button" class="btn btn-secondary" onclick="prevStep(2)">{{t "setup.back"}}</button>
					<button type="button" class="btn btn-primary" onclick="nextStep(2)">{{t "setup.next"}}</button>
				</div>
			</div>

			<!-- Step 3: Server Configuration -->
			<div id="step-3" class="wizard-step hidden">
				<h2>{{t "setup.server_configuration"}}</h2>
				<div class="form-group">
					<label for="app_name">{{t "setup.application_name"}}</label>
					<input type="text" id="app_name" name="app_name" value="casspeed">
				</div>
				<div class="form-group">
					<label for="domain">{{t "setup.domain"}}</label>
					<input type="text" id="domain" name="domain" placeholder="speedtest.example.com">
					<div class="form-hint">{{t "setup.domain_hint"}}</div>
				</div>
				<div class="form-group">
					<label for="mode">{{t "mode"}}</label>
					<select id="mode" name="mode">
						<option value="production">{{t "production"}}</option>
						<option value="development">{{t "development"}}</option>
					</select>
				</div>
				<div class="form-group">
					<label for="timezone">{{t "setup.timezone"}}</label>
					<select id="timezone" name="timezone">
						<option value="America/New_York">America/New_York ({{t "setup.timezone.eastern"}})</option>
						<option value="America/Chicago">America/Chicago ({{t "setup.timezone.central"}})</option>
						<option value="America/Denver">America/Denver ({{t "setup.timezone.mountain"}})</option>
						<option value="America/Los_Angeles">America/Los_Angeles ({{t "setup.timezone.pacific"}})</option>
						<option value="UTC">{{t "setup.timezone.utc"}}</option>
						<option value="Europe/London">Europe/London</option>
						<option value="Europe/Paris">Europe/Paris</option>
						<option value="Asia/Tokyo">Asia/Tokyo</option>
					</select>
				</div>
				<div class="btn-group">
					<button type="button" class="btn btn-secondary" onclick="prevStep(3)">{{t "setup.back"}}</button>
					<button type="button" class="btn btn-primary" onclick="nextStep(3)">{{t "setup.next"}}</button>
				</div>
			</div>

			<!-- Step 4: Security Settings -->
			<div id="step-4" class="wizard-step hidden">
				<h2>{{t "setup.security_settings"}}</h2>
				<div class="form-group">
					<label for="backup_password">{{t "setup.backup_password"}}</label>
					<input type="password" id="backup_password" name="backup_password">
					<div class="form-hint">{{t "setup.backup_password_hint"}}</div>
				</div>
				<div class="form-group checkbox-group">
					<input type="checkbox" id="enable_2fa" name="enable_2fa">
					<label for="enable_2fa">{{t "setup.enable_2fa"}}</label>
				</div>
				<div class="btn-group">
					<button type="button" class="btn btn-secondary" onclick="prevStep(4)">{{t "setup.back"}}</button>
					<button type="button" class="btn btn-primary" onclick="nextStep(4)">{{t "setup.next"}}</button>
				</div>
			</div>

			<!-- Step 5: Complete -->
			<div id="step-5" class="wizard-step hidden">
				<div class="success">
					<h2>{{t "setup.complete_title"}}</h2>
					<p>{{t "setup.complete_lead"}}</p>
				</div>
				<div class="btn-group">
					<button type="button" class="btn btn-primary" onclick="completeSetup()">{{t "setup.go_dashboard"}}</button>
				</div>
			</div>
		</div>
	</div>

	<script>
		let currentStep = 1;
		let apiToken = '';
		let setupData = {};

		function updateStepIndicators() {
			for (let i = 1; i <= 5; i++) {
				const indicator = document.getElementById('step-indicator-' + i);
				indicator.classList.remove('active', 'completed');
				if (i < currentStep) {
					indicator.classList.add('completed');
				} else if (i === currentStep) {
					indicator.classList.add('active');
				}
			}
		}

		function showStep(step) {
			for (let i = 1; i <= 5; i++) {
				document.getElementById('step-' + i).classList.add('hidden');
			}
			document.getElementById('step-' + step).classList.remove('hidden');
			currentStep = step;
			updateStepIndicators();
		}

		function nextStep(current) {
			if (current === 1) {
				// Validate admin credentials
				const username = document.getElementById('admin_username').value;
				const password = document.getElementById('admin_password').value;
				const confirm = document.getElementById('admin_password_confirm').value;

				if (!username || username.length < 3) {
					alert('{{t "setup.js.username_min"}}');
					return;
				}
				if (!password || password.length < 8) {
					alert('{{t "setup.js.password_min"}}');
					return;
				}
				if (password !== confirm) {
					alert('{{t "setup.js.password_mismatch"}}');
					return;
				}

				setupData.admin_username = username;
				setupData.admin_password = password;

				// Generate API token
				const alphabet = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
				const randomValues = crypto.getRandomValues(new Uint8Array(32));
				apiToken = 'adm_' + Array.from(randomValues, value => alphabet[value % alphabet.length]).join('');
				document.getElementById('api-token').textContent = apiToken;
				setupData.admin_api_token = apiToken;
			}

			if (current === 3) {
				setupData.app_name = document.getElementById('app_name').value;
				setupData.domain = document.getElementById('domain').value;
				setupData.mode = document.getElementById('mode').value;
				setupData.timezone = document.getElementById('timezone').value;
			}

			if (current === 4) {
				setupData.backup_encryption_password = document.getElementById('backup_password').value;
				setupData.enable_2fa = document.getElementById('enable_2fa').checked;

				// Submit setup data
				submitSetup();
				return;
			}

			showStep(current + 1);
		}

		function prevStep(current) {
			showStep(current - 1);
		}

		function copyToken() {
			navigator.clipboard.writeText(apiToken).then(() => {
				alert('{{t "setup.js.token_copied"}}');
			});
		}

		function submitSetup() {
			fetch('{{.AdminRoot}}/setup/complete', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify(setupData)
			})
			.then(response => response.json())
			.then(data => {
				if (data.success) {
					showStep(5);
				} else {
					alert('{{t "setup.js.setup_failed"}} ' + (data.error || '{{t "setup.js.unknown_error"}}'));
				}
			})
			.catch(err => {
				alert('{{t "setup.js.setup_failed"}} ' + err.message);
			});
		}

		function completeSetup() {
			window.location.href = '{{.AdminRoot}}';
		}
	</script>
</body>
</html>`

	lang, _ := data["Lang"].(string)
	direction, _ := data["Direction"].(string)
	tFunc, _ := data["T"].(func(string) string)
	data["Lang"] = lang
	data["Direction"] = direction
	parsed, err := template.New("setup-wizard").Funcs(template.FuncMap{"t": tFunc}).Parse(tmpl)
	if err != nil {
		http.Error(w, tFunc("setup.error.template"), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := parsed.Execute(w, data); err != nil {
		return
	}
}

// Helper functions

func setupValidationMessage(r *http.Request, err error) string {
	if err == nil {
		return adminText(r, "setup.error.invalid_request")
	}
	keys := map[string]string{
		"admin username is required":                   "setup.validation.username_required",
		"admin username must be 3-30 characters":       "setup.validation.username_length",
		"admin password is required":                   "setup.validation.password_required",
		"admin password must be at least 8 characters": "setup.validation.password_min",
		"mode must be 'production' or 'development'":   "setup.validation.mode_invalid",
	}
	if key, ok := keys[err.Error()]; ok {
		return adminText(r, key)
	}
	return adminText(r, "setup.error.invalid_request")
}

func generateAPIToken() (string, error) {
	const alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	token := make([]byte, 32)
	limit := big.NewInt(int64(len(alphabet)))
	for index := range token {
		randomIndex, err := rand.Int(rand.Reader, limit)
		if err != nil {
			return "", err
		}
		token[index] = alphabet[randomIndex.Int64()]
	}
	return "adm_" + string(token), nil
}

func validAdminTokenFormat(token string) bool {
	if len(token) != 36 || !strings.HasPrefix(token, "adm_") {
		return false
	}
	for _, character := range token[4:] {
		if !strings.ContainsRune("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz", character) {
			return false
		}
	}
	return true
}

func hashPassword(password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	hash := argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)
	return hex.EncodeToString(salt) + ":" + hex.EncodeToString(hash), nil
}

func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return xff
	}
	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}
	// Fall back to RemoteAddr
	return r.RemoteAddr
}
