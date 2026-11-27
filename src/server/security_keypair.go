package server

import (
	"bytes"
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/casapps/casspeed/src/server/store"
)

const securityPGPExpiry = 2 * 365 * 24 * time.Hour
const securityPGPOldKeyRetention = 30 * 24 * time.Hour

// securityKeypairStore is implemented by the persistent server store.
type securityKeypairStore interface {
	GetSecurityKeypairMetadata(context.Context) (*store.SecurityKeypairMetadata, error)
	SaveSecurityKeypairMetadata(context.Context, store.SecurityKeypairMetadata) error
	RotateSecurityKeypair(context.Context, store.SecurityKeypairMetadata, func([]byte) ([]byte, error)) error
}

// SecurityKeypairManager owns the project OpenPGP keypair and its config-dir files.
type SecurityKeypairManager struct {
	mu                 sync.Mutex
	configDir          string
	installationSecret []byte
	identityName       string
	securityEmail      string
	store              securityKeypairStore
	publish            bool
}

// NewSecurityKeypairManager validates dependencies and recovers an interrupted staged rotation.
func NewSecurityKeypairManager(configDir string, installationSecret []byte, identityName, securityEmail string, st securityKeypairStore) (*SecurityKeypairManager, error) {
	if strings.TrimSpace(configDir) == "" || len(installationSecret) != 32 || st == nil {
		return nil, errors.New("config directory, installation secret, and key metadata store are required")
	}
	if strings.ContainsAny(identityName, "()<>") || strings.ContainsAny(securityEmail, "()<>") || strings.TrimSpace(identityName) == "" || strings.TrimSpace(securityEmail) == "" {
		return nil, errors.New("invalid security key identity")
	}
	manager := &SecurityKeypairManager{configDir: filepath.Join(configDir, "security"), installationSecret: append([]byte(nil), installationSecret...), identityName: identityName, securityEmail: securityEmail, store: st, publish: true}
	if err := os.MkdirAll(manager.configDir, 0700); err != nil {
		return nil, fmt.Errorf("create security key directory: %w", err)
	}
	if err := os.Chmod(manager.configDir, 0700); err != nil {
		return nil, fmt.Errorf("secure security key directory: %w", err)
	}
	if err := manager.recoverStaged(context.Background()); err != nil {
		return nil, fmt.Errorf("recover security key rotation: %w", err)
	}
	return manager, nil
}

// SetPublishEnabled controls public key delivery per web.security.publish_pgp_key.
func (m *SecurityKeypairManager) SetPublishEnabled(enabled bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.publish = enabled
}

// Metadata returns stored key state without exposing private material.
func (m *SecurityKeypairManager) Metadata(ctx context.Context) (*store.SecurityKeypairMetadata, error) {
	return m.store.GetSecurityKeypairMetadata(ctx)
}

// Generate creates the initial Ed25519/Curve25519 keypair and installs it atomically.
func (m *SecurityKeypairManager) Generate(ctx context.Context, now time.Time) (*store.SecurityKeypairMetadata, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	metadata, err := m.store.GetSecurityKeypairMetadata(ctx)
	if err != nil {
		return nil, err
	}
	if metadata != nil && !metadata.Revoked {
		return nil, errors.New("security keypair already exists; use rotation")
	}
	entity, publicKey, privateKey, fingerprint, err := m.generate(now)
	if err != nil {
		return nil, err
	}
	_ = entity
	metadata = &store.SecurityKeypairMetadata{Fingerprint: fingerprint, CreatedAt: now.UTC(), ExpiresAt: now.UTC().Add(securityPGPExpiry), KeyserversPublished: "[]"}
	if err := m.writeStaged(publicKey, privateKey); err != nil {
		return nil, err
	}
	if err := m.store.SaveSecurityKeypairMetadata(ctx, *metadata); err != nil {
		m.removeStaged()
		return nil, fmt.Errorf("commit security key metadata: %w", err)
	}
	if err := m.finishStaged(); err != nil {
		return nil, err
	}
	return metadata, nil
}

// Rotate stages a fresh key, saves its metadata commit marker, then atomically switches active files.
func (m *SecurityKeypairManager) Rotate(ctx context.Context, now time.Time) (*store.SecurityKeypairMetadata, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	old, err := m.store.GetSecurityKeypairMetadata(ctx)
	if err != nil {
		return nil, err
	}
	if old == nil || old.Revoked {
		return nil, errors.New("security keypair is not available to rotate")
	}
	oldPrivatePath := filepath.Join(m.configDir, "pgp.priv.old.asc.enc")
	if _, statErr := os.Stat(oldPrivatePath); statErr == nil {
		if old.LastRotatedAt == nil || now.Before(old.LastRotatedAt.Add(securityPGPOldKeyRetention)) {
			return nil, errors.New("previous project private key must be retained for its 30-day grace period")
		}
		if err := os.Remove(oldPrivatePath); err != nil && !os.IsNotExist(err) {
			return nil, fmt.Errorf("remove expired previous project key: %w", err)
		}
	} else if !os.IsNotExist(statErr) {
		return nil, fmt.Errorf("inspect previous project key: %w", statErr)
	}
	oldEntity, err := m.loadEntity()
	if err != nil {
		return nil, fmt.Errorf("load existing project key: %w", err)
	}
	newEntity, publicKey, privateKey, fingerprint, err := m.generate(now)
	if err != nil {
		return nil, err
	}
	privateEntities, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(privateKey))
	if err != nil || len(privateEntities) != 1 {
		return nil, errors.New("generated private key could not be validated")
	}
	newEntity = privateEntities[0]
	if err := m.writeStaged(publicKey, privateKey); err != nil {
		return nil, err
	}
	rotatedAt := now.UTC()
	metadata := store.SecurityKeypairMetadata{Fingerprint: fingerprint, CreatedAt: rotatedAt, ExpiresAt: rotatedAt.Add(securityPGPExpiry), LastRotatedAt: &rotatedAt, KeyserversPublished: "[]"}
	if err := m.store.RotateSecurityKeypair(ctx, metadata, func(ciphertext []byte) ([]byte, error) {
		plaintext, err := decryptOpenPGP(oldEntity, ciphertext)
		if err != nil {
			return nil, err
		}
		return encryptOpenPGP(newEntity, plaintext)
	}); err != nil {
		m.removeStaged()
		return nil, fmt.Errorf("re-encrypt reports and commit rotated key metadata: %w", err)
	}
	if err := m.preserveOldPrivate(); err != nil {
		return nil, err
	}
	if err := m.finishStaged(); err != nil {
		return nil, err
	}
	return &metadata, nil
}

func (m *SecurityKeypairManager) generate(now time.Time) (*openpgp.Entity, []byte, []byte, string, error) {
	config := &packet.Config{Algorithm: packet.PubKeyAlgoEd25519, Curve: packet.Curve25519, DefaultHash: crypto.SHA256, DefaultCipher: packet.CipherAES256, KeyLifetimeSecs: uint32(securityPGPExpiry.Seconds()), Time: func() time.Time { return now.UTC() }}
	entity, err := openpgp.NewEntity(m.identityName, "Security", m.securityEmail, config)
	if err != nil {
		return nil, nil, nil, "", fmt.Errorf("generate OpenPGP entity: %w", err)
	}
	var public bytes.Buffer
	writer, err := armor.Encode(&public, openpgp.PublicKeyType, nil)
	if err != nil {
		return nil, nil, nil, "", err
	}
	if err := entity.Serialize(writer); err != nil {
		writer.Close()
		return nil, nil, nil, "", fmt.Errorf("serialize public key: %w", err)
	}
	if err := writer.Close(); err != nil {
		return nil, nil, nil, "", fmt.Errorf("finish public key armor: %w", err)
	}
	var private bytes.Buffer
	writer, err = armor.Encode(&private, openpgp.PrivateKeyType, nil)
	if err != nil {
		return nil, nil, nil, "", err
	}
	if err := entity.SerializePrivate(writer, config); err != nil {
		writer.Close()
		return nil, nil, nil, "", fmt.Errorf("serialize private key: %w", err)
	}
	if err := writer.Close(); err != nil {
		return nil, nil, nil, "", fmt.Errorf("finish private key armor: %w", err)
	}
	fingerprint := strings.ToUpper(hex.EncodeToString(entity.PrimaryKey.Fingerprint))
	return entity, public.Bytes(), private.Bytes(), fingerprint, nil
}

// PublicKey returns the verified ASCII-armored public key and active metadata.
func (m *SecurityKeypairManager) PublicKey(ctx context.Context) ([]byte, *store.SecurityKeypairMetadata, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	metadata, err := m.store.GetSecurityKeypairMetadata(ctx)
	if err != nil || metadata == nil || metadata.Revoked {
		return nil, metadata, err
	}
	data, err := os.ReadFile(filepath.Join(m.configDir, "pgp.pub.asc"))
	if err != nil {
		return nil, nil, err
	}
	entities, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(data))
	if err != nil || len(entities) != 1 || strings.ToUpper(hex.EncodeToString(entities[0].PrimaryKey.Fingerprint)) != metadata.Fingerprint {
		return nil, nil, errors.New("security public key does not match stored fingerprint")
	}
	return data, metadata, nil
}

// Fingerprint returns the full uppercase fingerprint for the active public key.
func (m *SecurityKeypairManager) Fingerprint(ctx context.Context) (string, error) {
	_, metadata, err := m.PublicKey(ctx)
	if err != nil {
		return "", err
	}
	if metadata == nil {
		return "", os.ErrNotExist
	}
	return metadata.Fingerprint, nil
}

// PGPKeyHandler serves the active public key only when publication is enabled.
func (m *SecurityKeypairManager) PGPKeyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		serverAuthError(w, r, http.StatusMethodNotAllowed, "auth.pages.security_method_not_allowed")
		return
	}
	m.mu.Lock()
	publish := m.publish
	m.mu.Unlock()
	if !publish {
		http.NotFound(w, r)
		return
	}
	key, _, err := m.PublicKey(r.Context())
	if err != nil || len(key) == 0 {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/pgp-keys; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	if r.Method == http.MethodGet {
		_, _ = w.Write(key)
	}
}

// Encrypt encrypts report content to the active project key and signs the ciphertext.
func (m *SecurityKeypairManager) Encrypt(plaintext []byte) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	entity, err := m.loadEntity()
	if err != nil {
		return nil, err
	}
	return encryptOpenPGP(entity, plaintext)
}

// Decrypt reads and verifies a report encrypted to the active project key.
func (m *SecurityKeypairManager) Decrypt(ciphertext []byte) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	entity, err := m.loadEntity()
	if err != nil {
		return nil, err
	}
	return decryptOpenPGP(entity, ciphertext)
}

func encryptOpenPGP(entity *openpgp.Entity, plaintext []byte) ([]byte, error) {
	var encrypted bytes.Buffer
	writer, err := openpgp.Encrypt(&encrypted, []*openpgp.Entity{entity}, entity, nil, nil)
	if err != nil {
		return nil, err
	}
	if _, err := writer.Write(plaintext); err != nil {
		writer.Close()
		return nil, err
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	return encrypted.Bytes(), nil
}

func decryptOpenPGP(entity *openpgp.Entity, ciphertext []byte) ([]byte, error) {
	message, err := openpgp.ReadMessage(bytes.NewReader(ciphertext), openpgp.EntityList{entity}, nil, nil)
	if err != nil {
		return nil, err
	}
	plaintext, err := io.ReadAll(io.LimitReader(message.UnverifiedBody, 1024*1024+1))
	if err != nil || len(plaintext) > 1024*1024 {
		return nil, errors.New("encrypted report is invalid or exceeds the size limit")
	}
	if message.SignatureError != nil {
		return nil, errors.New("encrypted report signature is invalid")
	}
	return plaintext, nil
}

// EncryptToPublicKey validates a supplied armored researcher key and encrypts a notification.
func EncryptToPublicKey(armoredKey, plaintext []byte) ([]byte, error) {
	entities, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(armoredKey))
	if err != nil || len(entities) != 1 {
		return nil, errors.New("invalid researcher OpenPGP public key")
	}
	var encrypted bytes.Buffer
	writer, err := openpgp.Encrypt(&encrypted, entities, nil, nil, nil)
	if err != nil {
		return nil, err
	}
	if _, err := writer.Write(plaintext); err != nil {
		writer.Close()
		return nil, err
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	return encrypted.Bytes(), nil
}

func (m *SecurityKeypairManager) loadEntity() (*openpgp.Entity, error) {
	privateFile, err := os.ReadFile(filepath.Join(m.configDir, "pgp.priv.asc.enc"))
	if err != nil {
		return nil, err
	}
	privateData, err := m.decryptPrivate(privateFile)
	if err != nil {
		return nil, err
	}
	entities, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(privateData))
	if err != nil || len(entities) != 1 {
		return nil, errors.New("stored OpenPGP private key is invalid")
	}
	metadata, err := m.store.GetSecurityKeypairMetadata(context.Background())
	if err != nil || metadata == nil || metadata.Revoked || strings.ToUpper(hex.EncodeToString(entities[0].PrimaryKey.Fingerprint)) != metadata.Fingerprint {
		return nil, errors.New("stored OpenPGP private key does not match active fingerprint")
	}
	return entities[0], nil
}

func (m *SecurityKeypairManager) encryptPrivate(plaintext []byte) ([]byte, error) {
	key := derivePrivateKeyEncryptionKey(m.installationSecret)
	block, err := aes.NewCipher(key)
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
	return gcm.Seal(nonce, nonce, plaintext, []byte("casspeed-project-pgp-private-v1")), nil
}

func (m *SecurityKeypairManager) decryptPrivate(ciphertext []byte) ([]byte, error) {
	key := derivePrivateKeyEncryptionKey(m.installationSecret)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < gcm.NonceSize() {
		return nil, errors.New("encrypted project key is truncated")
	}
	nonce := ciphertext[:gcm.NonceSize()]
	return gcm.Open(nil, nonce, ciphertext[gcm.NonceSize():], []byte("casspeed-project-pgp-private-v1"))
}

func derivePrivateKeyEncryptionKey(secret []byte) []byte {
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte("casspeed-project-pgp-private-v1"))
	return mac.Sum(nil)
}

func (m *SecurityKeypairManager) writeStaged(publicKey, privateKey []byte) error {
	encryptedPrivate, err := m.encryptPrivate(privateKey)
	if err != nil {
		return err
	}
	if err := writePrivateFile(filepath.Join(m.configDir, "pgp.pub.asc.new"), publicKey); err != nil {
		return err
	}
	if err := writePrivateFile(filepath.Join(m.configDir, "pgp.priv.asc.enc.new"), encryptedPrivate); err != nil {
		_ = os.Remove(filepath.Join(m.configDir, "pgp.pub.asc.new"))
		return err
	}
	return nil
}

func writePrivateFile(path string, data []byte) error {
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".pgp-key-*.tmp")
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer os.Remove(name)
	if err := temporary.Chmod(0600); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

func (m *SecurityKeypairManager) finishStaged() error {
	publicPath := filepath.Join(m.configDir, "pgp.pub.asc")
	privatePath := filepath.Join(m.configDir, "pgp.priv.asc.enc")
	if err := os.Rename(filepath.Join(m.configDir, "pgp.pub.asc.new"), publicPath); err != nil {
		return err
	}
	if err := os.Rename(filepath.Join(m.configDir, "pgp.priv.asc.enc.new"), privatePath); err != nil {
		return err
	}
	return nil
}

func (m *SecurityKeypairManager) removeStaged() {
	_ = os.Remove(filepath.Join(m.configDir, "pgp.pub.asc.new"))
	_ = os.Remove(filepath.Join(m.configDir, "pgp.priv.asc.enc.new"))
}

func (m *SecurityKeypairManager) preserveOldPrivate() error {
	privatePath := filepath.Join(m.configDir, "pgp.priv.asc.enc")
	if _, err := os.Stat(privatePath); err == nil {
		oldPath := filepath.Join(m.configDir, "pgp.priv.old.asc.enc")
		_ = os.Remove(oldPath)
		if err := os.Rename(privatePath, oldPath); err != nil {
			return err
		}
	}
	return nil
}

func (m *SecurityKeypairManager) recoverStaged(ctx context.Context) error {
	stagedPublic := filepath.Join(m.configDir, "pgp.pub.asc.new")
	stagedPrivate := filepath.Join(m.configDir, "pgp.priv.asc.enc.new")
	_, publicErr := os.Stat(stagedPublic)
	_, privateErr := os.Stat(stagedPrivate)
	if os.IsNotExist(publicErr) && os.IsNotExist(privateErr) {
		return nil
	}
	metadata, err := m.store.GetSecurityKeypairMetadata(ctx)
	if err != nil {
		return err
	}
	if metadata == nil {
		m.removeStaged()
		return nil
	}
	publicBytes, privateBytes, err := m.findKeypairForFingerprint(metadata.Fingerprint)
	if err != nil {
		return fmt.Errorf("recover key files for committed fingerprint %s: %w", metadata.Fingerprint, err)
	}
	if err := m.writeStaged(publicBytes, privateBytes); err != nil {
		return err
	}
	if currentPrivate, err := os.ReadFile(filepath.Join(m.configDir, "pgp.priv.asc.enc")); err == nil {
		decrypted, decErr := m.decryptPrivate(currentPrivate)
		if decErr == nil {
			entities, parseErr := openpgp.ReadArmoredKeyRing(bytes.NewReader(decrypted))
			if parseErr == nil && len(entities) == 1 && strings.ToUpper(hex.EncodeToString(entities[0].PrimaryKey.Fingerprint)) != metadata.Fingerprint {
				if err := m.preserveOldPrivate(); err != nil {
					return err
				}
			}
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	return m.finishStaged()
}

func (m *SecurityKeypairManager) findKeypairForFingerprint(fingerprint string) ([]byte, []byte, error) {
	publicFiles := []string{"pgp.pub.asc.new", "pgp.pub.asc"}
	privateFiles := []string{"pgp.priv.asc.enc.new", "pgp.priv.asc.enc"}
	for _, publicName := range publicFiles {
		publicBytes, err := os.ReadFile(filepath.Join(m.configDir, publicName))
		if err != nil {
			continue
		}
		publicEntities, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(publicBytes))
		if err != nil || len(publicEntities) != 1 || strings.ToUpper(hex.EncodeToString(publicEntities[0].PrimaryKey.Fingerprint)) != fingerprint {
			continue
		}
		for _, privateName := range privateFiles {
			privateBytes, err := os.ReadFile(filepath.Join(m.configDir, privateName))
			if err != nil {
				continue
			}
			decrypted, err := m.decryptPrivate(privateBytes)
			if err != nil {
				continue
			}
			privateEntities, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(decrypted))
			if err == nil && len(privateEntities) == 1 && strings.ToUpper(hex.EncodeToString(privateEntities[0].PrimaryKey.Fingerprint)) == fingerprint {
				return publicBytes, decrypted, nil
			}
		}
	}
	return nil, nil, errors.New("matching public and private key files were not found")
}

// Delete removes the active keypair after the caller verifies the explicit confirmation phrase.
func (m *SecurityKeypairManager) Delete(ctx context.Context, confirmation string) error {
	if confirmation != "DELETE SECURITY KEYPAIR" {
		return errors.New("confirmation phrase does not match")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	metadata, err := m.store.GetSecurityKeypairMetadata(ctx)
	if err != nil || metadata == nil {
		return err
	}
	metadata.Revoked = true
	if err := m.store.SaveSecurityKeypairMetadata(ctx, *metadata); err != nil {
		return err
	}
	m.publish = false
	for _, name := range []string{"pgp.pub.asc", "pgp.priv.asc.enc", "pgp.priv.old.asc.enc", "pgp.pub.asc.new", "pgp.priv.asc.enc.new"} {
		if err := os.Remove(filepath.Join(m.configDir, name)); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}

// CleanupOldPrivateKey removes the encrypted previous key after its 30-day grace period.
func (m *SecurityKeypairManager) CleanupOldPrivateKey(now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	metadata, err := m.store.GetSecurityKeypairMetadata(context.Background())
	if err != nil || metadata == nil || metadata.LastRotatedAt == nil || now.Before(metadata.LastRotatedAt.Add(securityPGPOldKeyRetention)) {
		return err
	}
	err = os.Remove(filepath.Join(m.configDir, "pgp.priv.old.asc.enc"))
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

// AdminKeypairHandler renders and processes the authenticated operator keypair page.
func (s *SecurityReportService) AdminKeypairHandler(w http.ResponseWriter, r *http.Request, manager *SecurityKeypairManager) {
	if manager == nil {
		serverAuthError(w, r, http.StatusServiceUnavailable, "auth.pages.keypair_unavailable")
		return
	}
	adminName, sessionID, ok := s.requireSecurityAdmin(w, r)
	if !ok {
		return
	}
	switch r.Method {
	case http.MethodGet:
		metadata, err := manager.Metadata(r.Context())
		if err != nil {
			serverAuthError(w, r, http.StatusInternalServerError, "auth.pages.security_load_failed")
			return
		}
		w.Header().Set("Cache-Control", "private, no-store")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		requestOrigin, _ := url.Parse(BuildURL(r, "/"))
		csrfToken := s.adminCSRFToken(sessionID)
		http.SetCookie(w, &http.Cookie{Name: "csrf_token", Value: csrfToken, Path: prefixPagePath(requestPathPrefix(r), "/"), Secure: requestOrigin != nil && requestOrigin.Scheme == "https", SameSite: http.SameSiteStrictMode, HttpOnly: false})
		language, direction := requestLanguage(r)
		labels := map[string]string{
			"title": serverAuthText(r, "auth.pages.keypair_title"), "fingerprint": serverAuthText(r, "auth.pages.keypair_fingerprint"),
			"skip":    serverAuthText(r, "nav.skip_to_content"),
			"created": serverAuthText(r, "auth.pages.keypair_created"), "expires": serverAuthText(r, "auth.pages.keypair_expires"),
			"download": serverAuthText(r, "auth.pages.keypair_download"), "rotate": serverAuthText(r, "auth.pages.keypair_rotate"),
			"delete_prompt": serverAuthText(r, "auth.pages.keypair_delete_prompt"), "delete": serverAuthText(r, "auth.pages.keypair_delete"),
			"missing": serverAuthText(r, "auth.pages.keypair_missing"), "generate": serverAuthText(r, "auth.pages.keypair_generate"),
		}
		if err := securityKeypairAdminTemplate.Execute(w, struct {
			Metadata            *store.SecurityKeypairMetadata
			CSRF                string
			Lang, Dir, BasePath string
			Labels              map[string]string
		}{metadata, csrfToken, language, direction, requestPathPrefix(r), labels}); err != nil {
			serverAuthError(w, r, http.StatusInternalServerError, "auth.pages.security_render_failed")
		}
	case http.MethodPost:
		r.Body = http.MaxBytesReader(w, r.Body, 8*1024)
		if err := r.ParseForm(); err != nil || !isSameOriginRequest(r) {
			s.logCSRFFailure(r, "origin_mismatch")
			serverAuthError(w, r, http.StatusForbidden, "auth.pages.security_csrf_failed")
			return
		}
		cookie, err := r.Cookie("csrf_token")
		if err != nil || !validAdminCSRFToken(sessionID, cookie.Value, r.Form.Get("csrf_token"), s.adminCSRFToken(sessionID)) {
			s.logCSRFFailure(r, "token_mismatch")
			serverAuthError(w, r, http.StatusForbidden, "auth.pages.security_csrf_failed")
			return
		}
		var metadata *store.SecurityKeypairMetadata
		switch r.FormValue("action") {
		case "generate":
			metadata, err = manager.Generate(r.Context(), time.Now())
		case "rotate":
			metadata, err = manager.Rotate(r.Context(), time.Now())
		case "delete":
			err = manager.Delete(r.Context(), r.FormValue("confirmation"))
		default:
			err = errors.New("unknown keypair action")
		}
		if err != nil {
			serverAuthError(w, r, http.StatusBadRequest, "auth.pages.keypair_action_failed")
			return
		}
		if s.securityLog != nil {
			s.securityLog("security.keypair_action", map[string]any{"admin": adminName, "action": r.FormValue("action"), "fingerprint": func() string {
				if metadata != nil {
					return metadata.Fingerprint
				}
				return ""
			}()})
		}
		http.Redirect(w, r, r.URL.Path, http.StatusSeeOther)
	default:
		w.Header().Set("Allow", "GET, POST")
		serverAuthError(w, r, http.StatusMethodNotAllowed, "auth.pages.security_method_not_allowed")
	}
}

var securityKeypairAdminTemplate = template.Must(template.New("security-keypair-admin").Parse(`<!doctype html><html lang="{{.Lang}}" dir="{{.Dir}}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{{index .Labels "title"}}</title><link rel="stylesheet" href="{{.BasePath}}/static/css/style.css"></head><body><a class="skip-link" href="#main-content">{{index .Labels "skip"}}</a><main id="main-content" class="container container-md"><h1>{{index .Labels "title"}}</h1>{{if .Metadata}}<p>{{index .Labels "fingerprint"}}: <code>{{.Metadata.Fingerprint}}</code></p><p>{{index .Labels "created"}}: <time>{{.Metadata.CreatedAt}}</time></p><p>{{index .Labels "expires"}}: <time>{{.Metadata.ExpiresAt}}</time></p><a href="{{.BasePath}}/.well-known/pgp-key.asc">{{index .Labels "download"}}</a><form method="post"><input type="hidden" name="csrf_token" value="{{.CSRF}}"><button name="action" value="rotate">{{index .Labels "rotate"}}</button></form><form method="post"><input type="hidden" name="csrf_token" value="{{.CSRF}}"><input type="hidden" name="action" value="delete"><label>{{index .Labels "delete_prompt"}} <input name="confirmation" required></label><button type="submit">{{index .Labels "delete"}}</button></form>{{else}}<p>{{index .Labels "missing"}}</p><form method="post"><input type="hidden" name="csrf_token" value="{{.CSRF}}"><button name="action" value="generate">{{index .Labels "generate"}}</button></form>{{end}}</main></body></html>`))

// PGPFingerprint returns the full v4 fingerprint of a valid armored public key.
func PGPFingerprint(armoredKey []byte) (string, error) {
	entities, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(armoredKey))
	if err != nil || len(entities) != 1 {
		return "", errors.New("invalid OpenPGP public key")
	}
	return strings.ToUpper(hex.EncodeToString(entities[0].PrimaryKey.Fingerprint)), nil
}

// ValidateResearcherPGPKey checks a supplied armored public key before any report is stored.
func ValidateResearcherPGPKey(armoredKey []byte) error {
	entities, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(armoredKey))
	if err != nil || len(entities) != 1 {
		return errors.New("invalid researcher OpenPGP public key")
	}
	if _, ok := entities[0].EncryptionKey(time.Now()); !ok {
		return errors.New("researcher OpenPGP key has no usable encryption key")
	}
	return nil
}

// SafeHTTPSKeyURL validates a keyserver URL without performing a network request.
func SafeHTTPSKeyURL(value string) (*url.URL, error) {
	parsed, err := url.ParseRequestURI(value)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" || strings.Contains(value, "#") {
		return nil, errors.New("invalid HTTPS key URL")
	}
	return parsed, nil
}
