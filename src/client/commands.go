package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/term"
	"gopkg.in/yaml.v3"
)

const clientName = "casspeed-cli"

var cliInteractive = func() bool { return term.IsTerminal(int(os.Stdin.Fd())) }

type clientOptions struct {
	serverURL string
	token     string
	output    string
	language  string
}

type speedResult struct {
	TestID     string  `json:"test_id"`
	Download   float64 `json:"download_mbps"`
	Upload     float64 `json:"upload_mbps"`
	Ping       float64 `json:"ping_ms"`
	Jitter     float64 `json:"jitter_ms"`
	PacketLoss float64 `json:"packet_loss"`
	ShareURL   string  `json:"share_url,omitempty"`
}

type apiEnvelope struct {
	OK      bool            `json:"ok"`
	Error   string          `json:"error"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data"`
}

type bearerTransport struct {
	base     http.RoundTripper
	token    string
	language string
}

func (t bearerTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if (t.token != "" && request.Header.Get("Authorization") == "") || (t.language != "" && request.Header.Get("Accept-Language") == "") {
		request = request.Clone(request.Context())
		if t.token != "" && request.Header.Get("Authorization") == "" {
			request.Header.Set("Authorization", "Bearer "+t.token)
		}
		if t.language != "" && request.Header.Get("Accept-Language") == "" {
			request.Header.Set("Accept-Language", t.language)
		}
	}
	return t.base.RoundTrip(request)
}

func execute(command string, args []string, options clientOptions, stdout, stderr io.Writer) int {
	base, err := url.Parse(strings.TrimRight(options.serverURL, "/"))
	if err != nil || (base.Scheme != "http" && base.Scheme != "https") || base.Host == "" || base.User != nil {
		fmt.Fprintln(stderr, "error: server URL must be an absolute http or https URL")
		return 2
	}
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Timeout: 30 * time.Second, Jar: jar, Transport: bearerTransport{base: http.DefaultTransport, token: options.token, language: options.language}}
	request := func(ctx context.Context, method, path string, body io.Reader) (*http.Response, error) {
		req, err := http.NewRequestWithContext(ctx, method, base.String()+path, body)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", clientName+"/"+Version)
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Accept-Language", options.language)
		if options.token != "" {
			req.Header.Set("Authorization", "Bearer "+options.token)
		}
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		return client.Do(req)
	}
	switch command {
	case "health":
		resp, err := request(context.Background(), http.MethodGet, "/api/healthz", nil)
		if err != nil {
			return reportError(stderr, err)
		}
		defer resp.Body.Close()
		return writeResponse(resp, options.output, stdout, stderr)
	case "history":
		resp, err := request(context.Background(), http.MethodGet, "/api/v1/speed-tests", nil)
		if err != nil {
			return reportError(stderr, err)
		}
		defer resp.Body.Close()
		return writeResponse(resp, options.output, stdout, stderr)
	case "login":
		if len(args) > 1 {
			fmt.Fprintln(stderr, "usage: casspeed-cli login [TOKEN]")
			return 2
		}
		token := options.token
		if len(args) == 1 {
			token = args[0]
		}
		if token == "" {
			fmt.Fprintln(stderr, "error: provide a token with --token or as the login argument")
			return 2
		}
		path, err := defaultTokenPath()
		if err != nil {
			return reportError(stderr, err)
		}
		if err := writePrivateToken(path, token); err != nil {
			return reportError(stderr, err)
		}
		fmt.Fprintf(stdout, "Saved API token to %s\n", path)
		return 0
	case "share":
		if len(args) != 1 {
			fmt.Fprintln(stderr, "usage: casspeed-cli share TEST_ID")
			return 2
		}
		resp, err := request(context.Background(), http.MethodPost, "/api/v1/speed-tests/"+url.PathEscape(args[0])+"/shares", bytes.NewBufferString(`{"include_username":false}`))
		if err != nil {
			return reportError(stderr, err)
		}
		defer resp.Body.Close()
		return writeResponse(resp, options.output, stdout, stderr)
	case "test":
		if len(args) != 0 {
			fmt.Fprintln(stderr, "usage: casspeed-cli test")
			return 2
		}
		result, err := runSpeedTest(base, client, jar, options.token, request, options.language)
		if err != nil {
			return reportError(stderr, err)
		}
		if options.output == "json" {
			if err := json.NewEncoder(stdout).Encode(result); err != nil {
				fmt.Fprintf(stderr, "error: %v\n", err)
				return 1
			}
			return 0
		}
		fmt.Fprintf(stdout, "Test %s\nDownload: %.2f Mbps\nUpload: %.2f Mbps\nPing: %.2f ms\nJitter: %.2f ms\nPacket loss: %.2f%%\n", result.TestID, result.Download, result.Upload, result.Ping, result.Jitter, result.PacketLoss)
		return 0
	default:
		fmt.Fprintf(stderr, "error: unknown command %q\n", command)
		return 2
	}
}

func runSpeedTest(base *url.URL, client *http.Client, jar http.CookieJar, token string, request func(context.Context, string, string, io.Reader) (*http.Response, error), languages ...string) (speedResult, error) {
	var result speedResult
	response, err := request(context.Background(), http.MethodPost, "/api/v1/speed-tests", nil)
	if err != nil {
		return result, err
	}
	var envelope apiEnvelope
	if err := json.NewDecoder(response.Body).Decode(&envelope); err != nil {
		response.Body.Close()
		return result, err
	}
	response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return result, fmt.Errorf("server returned %s: %s", response.Status, envelope.Message)
	}
	var initial struct {
		TestID   string `json:"test_id"`
		Duration int    `json:"duration_seconds"`
	}
	if err := json.Unmarshal(envelope.Data, &initial); err != nil || initial.TestID == "" {
		return result, errors.New("server returned an invalid speed test response")
	}
	result.TestID = initial.TestID
	duration := time.Duration(initial.Duration) * time.Second
	if duration <= 0 || duration > 2*time.Minute {
		duration = 10 * time.Second
	}
	result.Ping, result.Jitter, result.PacketLoss = measureLatency(base, client)
	result.Download = measureTransfer(base, client, initial.TestID, "download", duration)
	result.Upload = measureTransfer(base, client, initial.TestID, "upload", duration)
	if err := submitResult(base, client, jar, token, initial.TestID, result, languages...); err != nil {
		return result, err
	}
	return result, nil
}

func measureLatency(base *url.URL, client *http.Client) (float64, float64, float64) {
	const attempts = 10
	var samples []float64
	for i := 0; i < attempts; i++ {
		started := time.Now()
		response, err := client.Get(base.String() + "/healthz")
		if err == nil {
			_, _ = io.Copy(io.Discard, response.Body)
			response.Body.Close()
			if response.StatusCode < 500 {
				samples = append(samples, float64(time.Since(started).Microseconds())/1000)
			}
		}
	}
	if len(samples) == 0 {
		return 0, 0, 100
	}
	var total, jitter float64
	for index, value := range samples {
		total += value
		if index > 0 {
			jitter += abs(value - samples[index-1])
		}
	}
	if len(samples) > 1 {
		jitter /= float64(len(samples) - 1)
	}
	return total / float64(len(samples)), jitter, 100 * float64(attempts-len(samples)) / attempts
}

func measureTransfer(base *url.URL, client *http.Client, testID, phase string, duration time.Duration) float64 {
	const blockSize = 1 << 20
	deadline := time.Now().Add(duration)
	var transferred int64
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		started := time.Now()
		var response *http.Response
		var err error
		var request *http.Request
		if phase == "download" {
			request, err = http.NewRequestWithContext(ctx, http.MethodGet, base.String()+"/api/v1/speed-tests/"+url.PathEscape(testID)+"/download?bytes="+fmt.Sprint(blockSize), nil)
		} else {
			payload := make([]byte, blockSize)
			if _, err = rand.Read(payload); err == nil {
				request, err = http.NewRequestWithContext(ctx, http.MethodPost, base.String()+"/api/v1/speed-tests/"+url.PathEscape(testID)+"/uploads", bytes.NewReader(payload))
				if err == nil {
					request.Header.Set("Content-Type", "application/octet-stream")
				}
			}
		}
		if err == nil {
			response, err = client.Do(request)
		}
		if err == nil {
			if response.StatusCode >= 200 && response.StatusCode < 300 {
				count, _ := io.Copy(io.Discard, response.Body)
				if phase == "download" {
					transferred += count
				} else {
					transferred += blockSize
				}
			} else {
				_, _ = io.Copy(io.Discard, response.Body)
			}
			response.Body.Close()
		}
		cancel()
		if time.Since(started) > duration+30*time.Second {
			break
		}
		if err != nil {
			break
		}
	}
	seconds := duration.Seconds()
	if seconds <= 0 {
		return 0
	}
	return float64(transferred*8) / seconds / 1_000_000
}

func submitResult(base *url.URL, client *http.Client, jar http.CookieJar, token, testID string, result speedResult, languages ...string) error {
	wsURL := *base
	if wsURL.Scheme == "https" {
		wsURL.Scheme = "wss"
	} else {
		wsURL.Scheme = "ws"
	}
	wsURL.Path = "/api/v1/speed-tests/" + url.PathEscape(testID) + "/status"
	header := make(http.Header)
	header.Set("Origin", base.Scheme+"://"+base.Host)
	header.Set("User-Agent", clientName+"/"+Version)
	if len(languages) > 0 && languages[0] != "" {
		header.Set("Accept-Language", languages[0])
	}
	if token != "" {
		header.Set("Authorization", "Bearer "+token)
	}
	for _, cookie := range jar.Cookies(base) {
		header.Add("Cookie", cookie.Name+"="+cookie.Value)
	}
	connection, _, err := websocket.DefaultDialer.Dial(wsURL.String(), header)
	if err != nil {
		return fmt.Errorf("connect to test result endpoint: %w", err)
	}
	defer connection.Close()
	if err := connection.WriteJSON(map[string]any{"type": "result", "download_mbps": result.Download, "upload_mbps": result.Upload, "ping_ms": result.Ping, "jitter_ms": result.Jitter, "packet_loss": result.PacketLoss}); err != nil {
		return err
	}
	var update map[string]any
	if err := connection.ReadJSON(&update); err != nil {
		return err
	}
	if update["stage"] != "complete" {
		return fmt.Errorf("server did not accept test result")
	}
	return nil
}

func writeResponse(response *http.Response, format string, stdout, stderr io.Writer) int {
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		var envelope apiEnvelope
		_ = json.NewDecoder(response.Body).Decode(&envelope)
		if response.StatusCode == http.StatusUnauthorized && (envelope.Error == "TOKEN_REVOKED" || envelope.Error == "TOKEN_EXPIRED") {
			deleteCachedToken()
			fmt.Fprintln(stderr, "error: your API token is no longer valid. Run 'casspeed-cli login' to re-authenticate.")
			return 77
		}
		fmt.Fprintf(stderr, "error: server returned %s: %s\n", response.Status, envelope.Message)
		return 1
	}
	if format == "json" {
		_, err := io.Copy(stdout, response.Body)
		if err != nil {
			return reportError(stderr, err)
		}
		return 0
	}
	var body any
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		return reportError(stderr, err)
	}
	encoded, err := json.MarshalIndent(body, "", "  ")
	if err != nil {
		return reportError(stderr, err)
	}
	_, _ = fmt.Fprintln(stdout, string(encoded))
	return 0
}

func resolveToken(explicit, tokenFile string) (string, error) {
	if explicit != "" {
		return explicit, nil
	}
	if tokenFile != "" {
		return readPrivateToken(tokenFile)
	}
	if token := os.Getenv("CASSPEED_TOKEN"); token != "" {
		return token, nil
	}
	path, err := defaultTokenPath()
	if err != nil {
		return "", err
	}
	return readPrivateToken(path)
}

func defaultTokenPath() (string, error) {
	configDir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("locate user config directory: %w", err)
	}
	return filepath.Join(configDir, "casapps", "casspeed", "token"), nil
}

func readPrivateToken(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	if info.Mode().Perm()&0077 != 0 {
		return "", fmt.Errorf("token file %s has permissions %o; run chmod 600 and retry", path, info.Mode().Perm())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

func writePrivateToken(path, token string) error {
	if strings.TrimSpace(token) == "" {
		return errors.New("token is empty")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	if err := os.Chmod(filepath.Dir(path), 0700); err != nil {
		return err
	}
	if err := os.WriteFile(path, []byte(strings.TrimSpace(token)+"\n"), 0600); err != nil {
		return err
	}
	return os.Chmod(path, 0600)
}

func deleteCachedToken() {
	if path, err := defaultTokenPath(); err == nil {
		_ = os.Remove(path)
	}
}

func reportError(stderr io.Writer, err error) int {
	fmt.Fprintf(stderr, "error: %v\n", err)
	return 1
}

func abs(value float64) float64 {
	if value < 0 {
		return -value
	}
	return value
}

type cliRelease struct {
	Version string `json:"version"`
	SHA256  string `json:"sha256"`
}

type cliAutodiscover struct {
	OK   bool `json:"ok"`
	Data struct {
		CLIVersions   map[string]cliRelease `json:"cli_versions"`
		CLIMinVersion string                `json:"cli_min_version"`
	} `json:"data"`
}

func checkAndUpdateCLI(serverURL, token, action string, originalArgs []string, stdin io.Reader, stdout, stderr io.Writer) (int, bool) {
	timeout := 5 * time.Second
	if action != "" {
		timeout = 20 * time.Second
	}
	release, minimum, err := discoverCLIReleaseWithTimeout(serverURL, token, runtime.GOOS, runtime.GOARCH, timeout)
	if err != nil {
		if action == "check" {
			fmt.Fprintf(stderr, "error: unable to check for CLI updates: %v\n", err)
			return 1, false
		}
		return 0, false
	}
	currentVersion := Version
	_, currentVersionValid := parseSemver(currentVersion)
	releaseAvailable := release.Version != ""
	latestAvailable := releaseAvailable && (!currentVersionValid || compareSemver(release.Version, currentVersion) > 0)
	minimumRequired := minimum != "" && (!currentVersionValid || compareSemver(currentVersion, minimum) < 0)
	if minimumRequired && releaseAvailable && compareSemver(release.Version, minimum) < 0 {
		fmt.Fprintf(stderr, "error: this server requires CLI version %s, but the highest available release is %s\n", minimum, release.Version)
		return 1, false
	}
	if action == "check" {
		if latestAvailable {
			fmt.Fprintf(stdout, "CLI update available: %s → %s\n", currentVersion, release.Version)
		} else if !releaseAvailable {
			fmt.Fprintf(stdout, "No CLI update is available for %s-%s\n", runtime.GOOS, runtime.GOARCH)
		} else {
			fmt.Fprintf(stdout, "CLI is up to date (%s)\n", currentVersion)
		}
		if minimumRequired && !latestAvailable {
			fmt.Fprintf(stderr, "error: this CLI is too old; the server requires %s — run '%s --update yes' to upgrade.\n", minimum, cliBinaryName())
			return 1, false
		}
		return 0, false
	}
	if !latestAvailable {
		if minimumRequired {
			fmt.Fprintf(stderr, "error: this CLI is too old; the server requires %s — run '%s --update yes' to upgrade.\n", minimum, cliBinaryName())
			return 1, false
		}
		return 0, false
	}

	interactive := cliInteractive()
	approved := false
	if interactive {
		approved = confirmCLIUpdate(stdin, stdout, release.Version)
	} else if action == "yes" && cliUpdateAutoEnabled() {
		approved = true
	}
	if !approved {
		if minimumRequired {
			fmt.Fprintf(stderr, "error: this CLI is too old; the server requires %s — run '%s --update yes' to upgrade.\n", minimum, cliBinaryName())
			return 1, false
		}
		if interactive {
			fmt.Fprintln(stdout, "CLI update skipped")
		}
		return 0, false
	}

	if err := installCLIRelease(serverURL, token, runtime.GOOS, runtime.GOARCH, release); err != nil {
		fmt.Fprintf(stderr, "error: CLI update failed: %v\n", err)
		return 1, false
	}
	if len(originalArgs) == 0 {
		originalArgs = append([]string{os.Args[0]}, os.Args[1:]...)
	}
	code, err := relaunchUpdatedCLI(originalArgs)
	if err != nil {
		fmt.Fprintf(stderr, "error: CLI updated, but could not restart: %v\n", err)
		return 1, false
	}
	return code, true
}

func discoverCLIRelease(serverURL, token, goos, goarch string) (cliRelease, string, error) {
	return discoverCLIReleaseWithTimeout(serverURL, token, goos, goarch, 20*time.Second)
}

func discoverCLIReleaseWithTimeout(serverURL, token, goos, goarch string, timeout time.Duration) (cliRelease, string, error) {
	parsed, err := url.Parse(strings.TrimSpace(serverURL))
	if err != nil || parsed.Host == "" || parsed.User != nil || (parsed.Scheme != "https" && !isLocalHTTP(parsed)) {
		return cliRelease{}, "", errors.New("updates require an HTTPS server URL (HTTP is allowed only for localhost)")
	}
	origin := &url.URL{Scheme: parsed.Scheme, Host: parsed.Host}
	client := &http.Client{
		Timeout: timeout,
		CheckRedirect: func(request *http.Request, via []*http.Request) error {
			if request.URL.Scheme != origin.Scheme || !strings.EqualFold(request.URL.Host, origin.Host) {
				return errors.New("update redirect changed server origin")
			}
			if len(via) >= 5 {
				return errors.New("too many update redirects")
			}
			return nil
		},
	}
	request, err := http.NewRequest(http.MethodGet, origin.String()+"/api/autodiscover", nil)
	if err != nil {
		return cliRelease{}, "", fmt.Errorf("create autodiscover request: %w", err)
	}
	request.Header.Set("User-Agent", clientName+"/"+Version)
	request.Header.Set("Accept", "application/json")
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	response, err := client.Do(request)
	if err != nil {
		return cliRelease{}, "", fmt.Errorf("request autodiscover: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return cliRelease{}, "", fmt.Errorf("autodiscover returned %s", response.Status)
	}
	var data cliAutodiscover
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&data); err != nil {
		return cliRelease{}, "", fmt.Errorf("decode autodiscover response: %w", err)
	}
	if !data.OK {
		return cliRelease{}, "", errors.New("autodiscover response was not successful")
	}
	if data.Data.CLIMinVersion != "" {
		if _, ok := parseSemver(data.Data.CLIMinVersion); !ok {
			return cliRelease{}, "", errors.New("autodiscover returned an invalid minimum CLI version")
		}
	}
	release, ok := data.Data.CLIVersions[goos+"-"+goarch]
	if !ok {
		return cliRelease{}, data.Data.CLIMinVersion, nil
	}
	if _, err := hex.DecodeString(release.SHA256); err != nil || len(release.SHA256) != sha256.Size*2 {
		return cliRelease{}, data.Data.CLIMinVersion, errors.New("autodiscover returned an invalid CLI checksum")
	}
	if _, ok := parseSemver(release.Version); !ok {
		return cliRelease{}, data.Data.CLIMinVersion, errors.New("autodiscover returned an invalid CLI version")
	}
	return release, data.Data.CLIMinVersion, nil
}

func installCLIRelease(serverURL, token, goos, goarch string, release cliRelease) error {
	parsed, err := url.Parse(strings.TrimSpace(serverURL))
	if err != nil || parsed.Host == "" || parsed.User != nil || (parsed.Scheme != "https" && !isLocalHTTP(parsed)) {
		return errors.New("updates require an HTTPS server URL (HTTP is allowed only for localhost)")
	}
	origin := &url.URL{Scheme: parsed.Scheme, Host: parsed.Host}
	projectOrg, projectName := moduleOrgAndName()
	orgTemp := filepath.Join(os.TempDir(), projectOrg)
	if err := os.MkdirAll(orgTemp, 0700); err != nil {
		return fmt.Errorf("create project temp directory: %w", err)
	}
	stageDir, err := os.MkdirTemp(orgTemp, projectName+"-")
	if err != nil {
		return fmt.Errorf("create update staging directory: %w", err)
	}
	defer os.RemoveAll(stageDir)
	if err := os.Chmod(stageDir, 0700); err != nil {
		return fmt.Errorf("protect update staging directory: %w", err)
	}
	stagedBinary := filepath.Join(stageDir, "cli.update.tmp")
	filename := projectName + "-cli-" + goos + "-" + goarch
	if goos == "windows" {
		filename += ".exe"
	}
	request, err := http.NewRequest(http.MethodGet, origin.String()+"/cli/binaries/"+url.PathEscape(filename), nil)
	if err != nil {
		return fmt.Errorf("create CLI binary request: %w", err)
	}
	request.Header.Set("User-Agent", clientName+"/"+Version)
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	client := &http.Client{
		Timeout: 2 * time.Minute,
		CheckRedirect: func(request *http.Request, via []*http.Request) error {
			if request.URL.Scheme != origin.Scheme || !strings.EqualFold(request.URL.Host, origin.Host) {
				return errors.New("binary redirect changed server origin")
			}
			if len(via) >= 5 {
				return errors.New("too many binary redirects")
			}
			return nil
		},
	}
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("download CLI binary: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("CLI binary download returned %s", response.Status)
	}
	const maxBinarySize = int64(256 << 20)
	if response.ContentLength > maxBinarySize {
		return errors.New("CLI binary exceeds the 256 MiB size limit")
	}
	staged, err := os.OpenFile(stagedBinary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return fmt.Errorf("create staged CLI binary: %w", err)
	}
	hasher := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(staged, hasher), io.LimitReader(response.Body, maxBinarySize+1))
	syncErr := staged.Sync()
	closeErr := staged.Close()
	if copyErr != nil {
		return fmt.Errorf("write staged CLI binary: %w", copyErr)
	}
	if syncErr != nil {
		return fmt.Errorf("sync staged CLI binary: %w", syncErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close staged CLI binary: %w", closeErr)
	}
	if written == 0 || written > maxBinarySize {
		return errors.New("CLI binary is empty or exceeds the 256 MiB size limit")
	}
	expected, _ := hex.DecodeString(release.SHA256)
	if subtle.ConstantTimeCompare(hasher.Sum(nil), expected) != 1 {
		return errors.New("CLI binary SHA-256 checksum did not match autodiscover")
	}
	executable, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate current CLI binary: %w", err)
	}
	if resolved, resolveErr := filepath.EvalSymlinks(executable); resolveErr == nil {
		executable = resolved
	}
	if err := replaceCLIExecutablePlatform(stagedBinary, executable); err != nil {
		if os.IsPermission(err) {
			return fmt.Errorf("you do not have permission to update %s; ask your admin or move the binary to a writable path", executable)
		}
		return fmt.Errorf("replace CLI binary at %s: %w", executable, err)
	}
	return nil
}

func replaceCLIExecutable(source, target string) error {
	return replaceCLIExecutablePlatform(source, target)
}

func relaunchUpdatedCLI(args []string) (int, error) {
	executable, err := os.Executable()
	if err != nil {
		return 1, fmt.Errorf("locate updated executable: %w", err)
	}
	if resolved, resolveErr := filepath.EvalSymlinks(executable); resolveErr == nil {
		executable = resolved
	}
	if len(args) == 0 {
		args = append([]string{executable}, os.Args[1:]...)
	}
	process, err := os.StartProcess(executable, args, &os.ProcAttr{Files: []*os.File{os.Stdin, os.Stdout, os.Stderr}, Env: os.Environ(), Dir: ""})
	if err != nil {
		return 1, err
	}
	state, err := process.Wait()
	if err != nil {
		return 1, err
	}
	return state.ExitCode(), nil
}

func confirmCLIUpdate(stdin io.Reader, stdout io.Writer, version string) bool {
	fmt.Fprintf(stdout, "CLI version %s is available. Update now? [y/N] ", version)
	answer, err := bufio.NewReader(stdin).ReadString('\n')
	if err != nil && len(answer) == 0 {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(answer), "y") || strings.EqualFold(strings.TrimSpace(answer), "yes")
}

func cliUpdateAutoEnabled() bool {
	tokenPath, err := defaultTokenPath()
	if err != nil {
		return false
	}
	data, err := os.ReadFile(filepath.Join(filepath.Dir(tokenPath), "cli.yml"))
	if err != nil {
		return false
	}
	var settings struct {
		Update struct {
			Auto bool `yaml:"auto"`
		} `yaml:"update"`
	}
	if yaml.Unmarshal(data, &settings) != nil {
		return false
	}
	return settings.Update.Auto
}

func isLocalHTTP(parsed *url.URL) bool {
	if parsed.Scheme != "http" {
		return false
	}
	host := strings.ToLower(parsed.Hostname())
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func moduleOrgAndName() (string, string) {
	if buildInfo, ok := debug.ReadBuildInfo(); ok && buildInfo.Main.Path != "" {
		parts := strings.Split(strings.Trim(buildInfo.Main.Path, "/"), "/")
		if len(parts) >= 2 {
			return parts[len(parts)-2], parts[len(parts)-1]
		}
	}
	return "local", strings.TrimSuffix(clientName, "-cli")
}

func cliBinaryName() string {
	_, name := moduleOrgAndName()
	return name + "-cli"
}

type semanticVersion struct {
	core       [3]uint64
	prerelease []string
}

func parseSemver(value string) (semanticVersion, bool) {
	var parsed semanticVersion
	value = strings.TrimSpace(strings.TrimPrefix(value, "v"))
	if plus := strings.IndexByte(value, '+'); plus >= 0 {
		value = value[:plus]
	}
	core := value
	if dash := strings.IndexByte(value, '-'); dash >= 0 {
		core = value[:dash]
		parsed.prerelease = strings.Split(value[dash+1:], ".")
		if len(parsed.prerelease) == 0 || parsed.prerelease[0] == "" {
			return semanticVersion{}, false
		}
	}
	parts := strings.Split(core, ".")
	if len(parts) != 3 {
		return semanticVersion{}, false
	}
	for index, part := range parts {
		if part == "" || len(part) > 1 && part[0] == '0' {
			return semanticVersion{}, false
		}
		number, err := strconv.ParseUint(part, 10, 64)
		if err != nil {
			return semanticVersion{}, false
		}
		parsed.core[index] = number
	}
	return parsed, true
}

func compareSemver(left, right string) int {
	a, okA := parseSemver(left)
	b, okB := parseSemver(right)
	if !okA || !okB {
		return 0
	}
	for index := range a.core {
		if a.core[index] > b.core[index] {
			return 1
		}
		if a.core[index] < b.core[index] {
			return -1
		}
	}
	if len(a.prerelease) == 0 && len(b.prerelease) > 0 {
		return 1
	}
	if len(a.prerelease) > 0 && len(b.prerelease) == 0 {
		return -1
	}
	for index := 0; index < len(a.prerelease) && index < len(b.prerelease); index++ {
		leftPart, rightPart := a.prerelease[index], b.prerelease[index]
		leftNumber, leftErr := strconv.ParseUint(leftPart, 10, 64)
		rightNumber, rightErr := strconv.ParseUint(rightPart, 10, 64)
		if leftErr == nil && rightErr == nil {
			if leftNumber > rightNumber {
				return 1
			}
			if leftNumber < rightNumber {
				return -1
			}
			continue
		}
		if leftErr == nil {
			return -1
		}
		if rightErr == nil {
			return 1
		}
		if leftPart > rightPart {
			return 1
		}
		if leftPart < rightPart {
			return -1
		}
	}
	if len(a.prerelease) > len(b.prerelease) {
		return 1
	}
	if len(a.prerelease) < len(b.prerelease) {
		return -1
	}
	return 0
}
