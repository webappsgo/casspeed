package graphql

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"strings"
	"time"

	"github.com/casapps/casspeed/src/server/model"
	graphqlgo "github.com/graph-gophers/graphql-go"
)

type Repository interface {
	GetSpeedTest(context.Context, string) (*model.SpeedTest, error)
	GetSpeedTestByShareCode(context.Context, string) (*model.SpeedTest, error)
	GetUserSpeedTests(context.Context, string, int, int) ([]*model.SpeedTest, error)
	GetSession(context.Context, string) (*model.Session, error)
	GetUser(context.Context, string) (*model.User, error)
}

type tokenRepository interface {
	GetAPITokenByToken(context.Context, string) (*model.APIToken, error)
}

type userSettingsRepository interface {
	GetOrCreateUserSettings(context.Context, string) (*model.UserSettings, error)
}

type userDevicesRepository interface {
	GetUserDevices(context.Context, string) ([]*model.Device, error)
}

type userTokensRepository interface {
	GetUserAPITokens(context.Context, string) ([]*model.APIToken, error)
}

type userSessionsRepository interface {
	ListUserSessions(context.Context, string) ([]*model.Session, error)
}

type userPasskeysRepository interface {
	GetPasskeys(context.Context, string, string) ([]*model.Passkey, error)
}

// Dependencies supplies the live application data used by GraphQL read resolvers.
type Dependencies struct {
	Store  Repository
	Health func(context.Context) (HealthSnapshot, error)
}

// HealthSnapshot is the public health representation returned by the shared health provider.
type HealthSnapshot struct {
	Project   HealthProjectSnapshot
	Status    string
	Version   string
	GoVersion string
	Build     HealthBuildSnapshot
	Uptime    string
	Mode      string
	Timestamp string
	Cluster   HealthClusterSnapshot
	Features  HealthFeaturesSnapshot
	Checks    HealthChecksSnapshot
	Stats     HealthStatsSnapshot
}

type HealthProjectSnapshot struct {
	Name        string
	Tagline     string
	Description string
}

type HealthBuildSnapshot struct {
	Commit string
	Date   string
}

type HealthClusterSnapshot struct {
	Enabled bool
	Status  string
}

type HealthFeaturesSnapshot struct {
	Geoip bool
	Tor   HealthTorSnapshot
	I2P   HealthI2PSnapshot
}

type HealthTorSnapshot struct {
	Enabled  bool
	Running  bool
	Status   string
	Hostname string
}

type HealthI2PSnapshot struct {
	Enabled  bool
	Running  bool
	State    string
	Status   string
	Hostname string
	Provider string
}

type HealthChecksSnapshot struct {
	Database  string
	Cache     string
	Disk      string
	Scheduler string
	I2P       string
}

type HealthStatsSnapshot struct {
	RequestsTotal     int32
	Requests24h       int32
	ActiveConnections int32
}

type HealthResolver struct{ snapshot HealthSnapshot }

func (r *HealthResolver) Project() *HealthProjectResolver {
	return &HealthProjectResolver{snapshot: r.snapshot.Project}
}
func (r *HealthResolver) Status() string    { return r.snapshot.Status }
func (r *HealthResolver) Version() string   { return r.snapshot.Version }
func (r *HealthResolver) GoVersion() string { return r.snapshot.GoVersion }
func (r *HealthResolver) Build() *HealthBuildResolver {
	return &HealthBuildResolver{snapshot: r.snapshot.Build}
}
func (r *HealthResolver) Uptime() string    { return r.snapshot.Uptime }
func (r *HealthResolver) Mode() string      { return r.snapshot.Mode }
func (r *HealthResolver) Timestamp() string { return r.snapshot.Timestamp }
func (r *HealthResolver) Cluster() *HealthClusterResolver {
	return &HealthClusterResolver{snapshot: r.snapshot.Cluster}
}
func (r *HealthResolver) Features() *HealthFeaturesResolver {
	return &HealthFeaturesResolver{snapshot: r.snapshot.Features}
}
func (r *HealthResolver) Checks() *HealthChecksResolver {
	return &HealthChecksResolver{snapshot: r.snapshot.Checks}
}
func (r *HealthResolver) Stats() *HealthStatsResolver {
	return &HealthStatsResolver{snapshot: r.snapshot.Stats}
}

type HealthProjectResolver struct{ snapshot HealthProjectSnapshot }

func (r *HealthProjectResolver) Name() string        { return r.snapshot.Name }
func (r *HealthProjectResolver) Tagline() string     { return r.snapshot.Tagline }
func (r *HealthProjectResolver) Description() string { return r.snapshot.Description }

type HealthBuildResolver struct{ snapshot HealthBuildSnapshot }

func (r *HealthBuildResolver) Commit() string { return r.snapshot.Commit }
func (r *HealthBuildResolver) Date() string   { return r.snapshot.Date }

type HealthClusterResolver struct{ snapshot HealthClusterSnapshot }

func (r *HealthClusterResolver) Enabled() bool  { return r.snapshot.Enabled }
func (r *HealthClusterResolver) Status() string { return r.snapshot.Status }

type HealthFeaturesResolver struct{ snapshot HealthFeaturesSnapshot }

func (r *HealthFeaturesResolver) Geoip() bool { return r.snapshot.Geoip }
func (r *HealthFeaturesResolver) Tor() *HealthTorResolver {
	return &HealthTorResolver{snapshot: r.snapshot.Tor}
}
func (r *HealthFeaturesResolver) I2p() *HealthI2PResolver {
	return &HealthI2PResolver{snapshot: r.snapshot.I2P}
}

type HealthTorResolver struct{ snapshot HealthTorSnapshot }

func (r *HealthTorResolver) Enabled() bool    { return r.snapshot.Enabled }
func (r *HealthTorResolver) Running() bool    { return r.snapshot.Running }
func (r *HealthTorResolver) Status() string   { return r.snapshot.Status }
func (r *HealthTorResolver) Hostname() string { return r.snapshot.Hostname }

type HealthI2PResolver struct{ snapshot HealthI2PSnapshot }

func (r *HealthI2PResolver) Enabled() bool    { return r.snapshot.Enabled }
func (r *HealthI2PResolver) Running() bool    { return r.snapshot.Running }
func (r *HealthI2PResolver) State() string    { return r.snapshot.State }
func (r *HealthI2PResolver) Status() string   { return r.snapshot.Status }
func (r *HealthI2PResolver) Hostname() string { return r.snapshot.Hostname }
func (r *HealthI2PResolver) Provider() string { return r.snapshot.Provider }

type HealthChecksResolver struct{ snapshot HealthChecksSnapshot }

func (r *HealthChecksResolver) Database() string  { return r.snapshot.Database }
func (r *HealthChecksResolver) Cache() string     { return r.snapshot.Cache }
func (r *HealthChecksResolver) Disk() string      { return r.snapshot.Disk }
func (r *HealthChecksResolver) Scheduler() string { return r.snapshot.Scheduler }
func (r *HealthChecksResolver) I2p() string       { return r.snapshot.I2P }

type HealthStatsResolver struct{ snapshot HealthStatsSnapshot }

func (r *HealthStatsResolver) RequestsTotal() int32     { return r.snapshot.RequestsTotal }
func (r *HealthStatsResolver) Requests24h() int32       { return r.snapshot.Requests24h }
func (r *HealthStatsResolver) ActiveConnections() int32 { return r.snapshot.ActiveConnections }

type Resolvers struct {
	store  Repository
	health func(context.Context) (HealthSnapshot, error)
}

type SpeedTestResult struct {
	ID           graphqlgo.ID
	Timestamp    string
	DownloadMbps float64
	UploadMbps   float64
	PingMs       float64
	JitterMs     float64
	PacketLoss   float64
}

type SpeedTestResolver struct{ result SpeedTestResult }

func (r *SpeedTestResolver) ID() graphqlgo.ID      { return r.result.ID }
func (r *SpeedTestResolver) Timestamp() string     { return r.result.Timestamp }
func (r *SpeedTestResolver) DownloadMbps() float64 { return r.result.DownloadMbps }
func (r *SpeedTestResolver) UploadMbps() float64   { return r.result.UploadMbps }
func (r *SpeedTestResolver) PingMs() float64       { return r.result.PingMs }
func (r *SpeedTestResolver) JitterMs() float64     { return r.result.JitterMs }
func (r *SpeedTestResolver) PacketLoss() float64   { return r.result.PacketLoss }

type UserProfileResolver struct{ user *model.User }

func (r *UserProfileResolver) ID() graphqlgo.ID        { return graphqlgo.ID(model.UserIDString(r.user.ID)) }
func (r *UserProfileResolver) Username() string        { return r.user.Username }
func (r *UserProfileResolver) Email() string           { return r.user.Email }
func (r *UserProfileResolver) EmailVerified() bool     { return r.user.EmailVerified }
func (r *UserProfileResolver) DisplayName() string     { return r.user.DisplayName }
func (r *UserProfileResolver) Bio() string             { return r.user.Bio }
func (r *UserProfileResolver) Location() string        { return r.user.Location }
func (r *UserProfileResolver) Website() string         { return r.user.Website }
func (r *UserProfileResolver) AvatarUrl() string       { return r.user.AvatarURL }
func (r *UserProfileResolver) Timezone() string        { return r.user.Timezone }
func (r *UserProfileResolver) Language() string        { return r.user.Language }
func (r *UserProfileResolver) Visibility() string      { return r.user.Visibility }
func (r *UserProfileResolver) OrgVisibility() bool     { return r.user.OrgVisibility }
func (r *UserProfileResolver) ShareShowUsername() bool { return r.user.ShareShowUsername }
func (r *UserProfileResolver) CreatedAt() string {
	return r.user.CreatedAt.UTC().Format(time.RFC3339Nano)
}

type UserSettingsResolver struct{ settings *model.UserSettings }

func (r *UserSettingsResolver) ShowEmail() bool       { return r.settings.ShowEmail }
func (r *UserSettingsResolver) ShowActivity() bool    { return r.settings.ShowActivity }
func (r *UserSettingsResolver) ShowOrgs() bool        { return r.settings.ShowOrgs }
func (r *UserSettingsResolver) Searchable() bool      { return r.settings.Searchable }
func (r *UserSettingsResolver) EmailSecurity() bool   { return r.settings.EmailSecurity }
func (r *UserSettingsResolver) EmailSession() bool    { return r.settings.EmailSession }
func (r *UserSettingsResolver) EmailMentions() bool   { return r.settings.EmailMentions }
func (r *UserSettingsResolver) EmailUpdates() bool    { return r.settings.EmailUpdates }
func (r *UserSettingsResolver) EmailNewsletter() bool { return r.settings.EmailNewsletter }
func (r *UserSettingsResolver) EmailDigest() string   { return r.settings.EmailDigest }
func (r *UserSettingsResolver) PushEnabled() bool     { return r.settings.PushEnabled }
func (r *UserSettingsResolver) PushMentions() bool    { return r.settings.PushMentions }
func (r *UserSettingsResolver) Theme() string         { return r.settings.Theme }
func (r *UserSettingsResolver) FontSize() string      { return r.settings.FontSize }
func (r *UserSettingsResolver) ReduceMotion() bool    { return r.settings.ReduceMotion }
func (r *UserSettingsResolver) DateFormat() string    { return r.settings.DateFormat }
func (r *UserSettingsResolver) TimeFormat() string    { return r.settings.TimeFormat }

type UserDeviceResolver struct{ device *model.Device }

func (r *UserDeviceResolver) ID() graphqlgo.ID { return graphqlgo.ID(r.device.ID) }
func (r *UserDeviceResolver) Name() string     { return r.device.Name }
func (r *UserDeviceResolver) LastSeen() string {
	return r.device.LastSeen.UTC().Format(time.RFC3339Nano)
}
func (r *UserDeviceResolver) CreatedAt() string {
	return r.device.CreatedAt.UTC().Format(time.RFC3339Nano)
}

type UserTokenResolver struct{ token *model.APIToken }

func (r *UserTokenResolver) ID() graphqlgo.ID    { return graphqlgo.ID(r.token.ID) }
func (r *UserTokenResolver) TokenPrefix() string { return r.token.TokenPrefix }
func (r *UserTokenResolver) Name() string        { return r.token.Name }
func (r *UserTokenResolver) Scope() string       { return r.token.Scope }
func (r *UserTokenResolver) ExpiresAt() *string {
	if r.token.ExpiresAt == nil {
		return nil
	}
	value := r.token.ExpiresAt.UTC().Format(time.RFC3339Nano)
	return &value
}
func (r *UserTokenResolver) LastUsed() string { return r.token.LastUsed.UTC().Format(time.RFC3339Nano) }
func (r *UserTokenResolver) CreatedAt() string {
	return r.token.CreatedAt.UTC().Format(time.RFC3339Nano)
}

type UserSecurityResolver struct {
	passwordConfigured bool
	activeSessions     int32
	passkeys           []*UserPasskeyResolver
}

func (r *UserSecurityResolver) PasswordConfigured() bool         { return r.passwordConfigured }
func (r *UserSecurityResolver) ActiveSessions() int32            { return r.activeSessions }
func (r *UserSecurityResolver) Passkeys() []*UserPasskeyResolver { return r.passkeys }

type UserPasskeyResolver struct{ passkey *model.Passkey }

func (r *UserPasskeyResolver) ID() graphqlgo.ID { return graphqlgo.ID(r.passkey.ID) }
func (r *UserPasskeyResolver) Name() string     { return r.passkey.Name }
func (r *UserPasskeyResolver) Active() bool     { return r.passkey.Active }
func (r *UserPasskeyResolver) CreatedAt() string {
	return r.passkey.CreatedAt.UTC().Format(time.RFC3339Nano)
}
func (r *UserPasskeyResolver) LastUsed() *string {
	if r.passkey.LastUsed == nil {
		return nil
	}
	value := r.passkey.LastUsed.UTC().Format(time.RFC3339Nano)
	return &value
}

type requestContextKey struct{}

type identity struct {
	userID    string
	ownerHash string
}

type resolverError struct {
	code    string
	message string
}

func (e *resolverError) Error() string { return e.message }

func (e *resolverError) Extensions() map[string]any {
	return map[string]any{"code": e.code}
}

func newResolvers(dependencies Dependencies) *Resolvers {
	return &Resolvers{store: dependencies.Store, health: dependencies.Health}
}

func (r *Resolvers) Health(ctx context.Context) (*HealthResolver, error) {
	if r.health == nil {
		return nil, &resolverError{code: "SERVER_ERROR", message: "Health data is unavailable"}
	}
	health, err := r.health(ctx)
	if err != nil {
		return nil, &resolverError{code: "SERVER_ERROR", message: "Health data is unavailable"}
	}
	return &HealthResolver{snapshot: health}, nil
}

func (r *Resolvers) SpeedTests(ctx context.Context, args struct{ Offset int32 }) ([]*SpeedTestResolver, error) {
	if r.store == nil {
		return nil, &resolverError{code: "SERVER_ERROR", message: "Test history is unavailable"}
	}
	identity, err := r.resolveIdentity(ctx)
	if err != nil {
		return nil, err
	}
	if identity.userID == "" {
		return nil, &resolverError{code: "UNAUTHORIZED", message: "Authentication required"}
	}
	if args.Offset < 0 || args.Offset > 1000000 {
		return nil, &resolverError{code: "INVALID_ARGUMENT", message: "Offset is outside the supported range"}
	}
	results, err := r.store.GetUserSpeedTests(ctx, identity.userID, 50, int(args.Offset))
	if err != nil {
		return nil, &resolverError{code: "SERVER_ERROR", message: "Unable to load test history"}
	}
	output := make([]*SpeedTestResolver, 0, len(results))
	for _, result := range results {
		if result != nil {
			output = append(output, safeSpeedTest(result))
		}
	}
	return output, nil
}

func (r *Resolvers) SpeedTest(ctx context.Context, args struct{ ID graphqlgo.ID }) (*SpeedTestResolver, error) {
	if r.store == nil {
		return nil, &resolverError{code: "SERVER_ERROR", message: "Test data is unavailable"}
	}
	result, err := r.store.GetSpeedTest(ctx, string(args.ID))
	if err != nil {
		return nil, &resolverError{code: "SERVER_ERROR", message: "Unable to load test result"}
	}
	if result == nil {
		return nil, nil
	}
	if result.ShareCode == "" {
		identity, identityErr := r.resolveIdentity(ctx)
		if identityErr != nil {
			return nil, identityErr
		}
		isAccountOwner := identity.userID != "" && identity.userID == result.UserID
		isAnonymousOwner := identity.ownerHash != "" && result.OwnerTokenHash != "" && subtle.ConstantTimeCompare([]byte(identity.ownerHash), []byte(result.OwnerTokenHash)) == 1
		if !isAccountOwner && !isAnonymousOwner {
			return nil, nil
		}
	}
	return safeSpeedTest(result), nil
}

func (r *Resolvers) SharedSpeedTest(ctx context.Context, args struct{ Code graphqlgo.ID }) (*SpeedTestResolver, error) {
	if r.store == nil {
		return nil, &resolverError{code: "SERVER_ERROR", message: "Shared results are unavailable"}
	}
	result, err := r.store.GetSpeedTestByShareCode(ctx, string(args.Code))
	if err != nil {
		return nil, &resolverError{code: "SERVER_ERROR", message: "Unable to load shared result"}
	}
	if result == nil {
		return nil, nil
	}
	return safeSpeedTest(result), nil
}

func (r *Resolvers) UserProfile(ctx context.Context) (*UserProfileResolver, error) {
	user, err := r.authenticatedUser(ctx)
	if err != nil {
		return nil, err
	}
	return &UserProfileResolver{user: user}, nil
}

func (r *Resolvers) UserSettings(ctx context.Context) (*UserSettingsResolver, error) {
	identity, err := r.requireUserIdentity(ctx)
	if err != nil {
		return nil, err
	}
	repository, ok := r.store.(userSettingsRepository)
	if !ok {
		return nil, &resolverError{code: "SERVER_ERROR", message: "Account settings are unavailable"}
	}
	settings, err := repository.GetOrCreateUserSettings(ctx, identity.userID)
	if err != nil || settings == nil {
		return nil, &resolverError{code: "SERVER_ERROR", message: "Unable to load account settings"}
	}
	return &UserSettingsResolver{settings: settings}, nil
}

func (r *Resolvers) UserSecurity(ctx context.Context) (*UserSecurityResolver, error) {
	user, err := r.authenticatedUser(ctx)
	if err != nil {
		return nil, err
	}
	identity, _ := r.resolveIdentity(ctx)
	activeSessions := int32(0)
	passkeyResolvers := make([]*UserPasskeyResolver, 0)
	if repository, ok := r.store.(userSessionsRepository); ok {
		sessions, err := repository.ListUserSessions(ctx, identity.userID)
		if err != nil {
			return nil, &resolverError{code: "SERVER_ERROR", message: "Unable to load account security"}
		}
		activeSessions = int32(len(sessions))
	}
	if repository, ok := r.store.(userPasskeysRepository); ok {
		passkeys, err := repository.GetPasskeys(ctx, "user", identity.userID)
		if err != nil {
			return nil, &resolverError{code: "SERVER_ERROR", message: "Unable to load account security"}
		}
		for _, passkey := range passkeys {
			if passkey != nil && passkey.UserType == "user" && passkey.UserID == identity.userID {
				passkeyResolvers = append(passkeyResolvers, &UserPasskeyResolver{passkey: passkey})
			}
		}
	}
	return &UserSecurityResolver{passwordConfigured: user.PasswordHash != "", activeSessions: activeSessions, passkeys: passkeyResolvers}, nil
}

func (r *Resolvers) UserDevices(ctx context.Context) ([]*UserDeviceResolver, error) {
	identity, err := r.requireUserIdentity(ctx)
	if err != nil {
		return nil, err
	}
	repository, ok := r.store.(userDevicesRepository)
	if !ok {
		return nil, &resolverError{code: "SERVER_ERROR", message: "Devices are unavailable"}
	}
	devices, err := repository.GetUserDevices(ctx, identity.userID)
	if err != nil {
		return nil, &resolverError{code: "SERVER_ERROR", message: "Unable to load devices"}
	}
	output := make([]*UserDeviceResolver, 0, len(devices))
	for _, device := range devices {
		if device != nil && device.UserID == identity.userID {
			output = append(output, &UserDeviceResolver{device: device})
		}
	}
	return output, nil
}

func (r *Resolvers) UserTokens(ctx context.Context) ([]*UserTokenResolver, error) {
	identity, err := r.requireUserIdentity(ctx)
	if err != nil {
		return nil, err
	}
	repository, ok := r.store.(userTokensRepository)
	if !ok {
		return nil, &resolverError{code: "SERVER_ERROR", message: "API tokens are unavailable"}
	}
	tokens, err := repository.GetUserAPITokens(ctx, identity.userID)
	if err != nil {
		return nil, &resolverError{code: "SERVER_ERROR", message: "Unable to load API tokens"}
	}
	output := make([]*UserTokenResolver, 0, len(tokens))
	for _, token := range tokens {
		if token != nil && token.UserID == identity.userID {
			output = append(output, &UserTokenResolver{token: token})
		}
	}
	return output, nil
}

func (r *Resolvers) authenticatedUser(ctx context.Context) (*model.User, error) {
	identity, err := r.requireUserIdentity(ctx)
	if err != nil {
		return nil, err
	}
	user, err := r.store.GetUser(ctx, identity.userID)
	if err != nil || user == nil {
		return nil, &resolverError{code: "SERVER_ERROR", message: "Unable to load account"}
	}
	return user, nil
}

func (r *Resolvers) requireUserIdentity(ctx context.Context) (identity, error) {
	if r.store == nil {
		return identity{}, &resolverError{code: "SERVER_ERROR", message: "Account data is unavailable"}
	}
	resolved, err := r.resolveIdentity(ctx)
	if err != nil {
		return identity{}, err
	}
	if resolved.userID == "" {
		return identity{}, &resolverError{code: "UNAUTHORIZED", message: "Authentication required"}
	}
	return resolved, nil
}

func (r *Resolvers) resolveIdentity(ctx context.Context) (identity, error) {
	request, ok := ctx.Value(requestContextKey{}).(*http.Request)
	if !ok || request == nil {
		return identity{}, &resolverError{code: "UNAUTHORIZED", message: "Authentication required"}
	}
	if r.store == nil {
		return identity{}, &resolverError{code: "SERVER_ERROR", message: "Authentication data is unavailable"}
	}
	if authorization := request.Header.Get("Authorization"); authorization != "" {
		const bearerPrefix = "Bearer "
		if !strings.HasPrefix(authorization, bearerPrefix) {
			return identity{}, nil
		}
		credential := strings.TrimPrefix(authorization, bearerPrefix)
		if !validUserTokenFormat(credential) {
			return identity{}, nil
		}
		tokens, ok := r.store.(tokenRepository)
		if !ok {
			return identity{}, &resolverError{code: "SERVER_ERROR", message: "Token validation is unavailable"}
		}
		token, tokenErr := tokens.GetAPITokenByToken(ctx, credential)
		if tokenErr != nil {
			return identity{}, &resolverError{code: "SERVER_ERROR", message: "Unable to validate bearer token"}
		}
		if token == nil || !validUserTokenScope(token.Scope) || token.ExpiresAt != nil && !token.ExpiresAt.After(time.Now()) {
			return identity{}, nil
		}
		user, userErr := r.store.GetUser(ctx, token.UserID)
		if userErr != nil {
			return identity{}, &resolverError{code: "SERVER_ERROR", message: "Unable to validate bearer token"}
		}
		if user == nil {
			return identity{}, nil
		}
		return identity{userID: model.UserIDString(user.ID)}, nil
	}
	if isNativeAPIRoute(request.URL.Path) {
		return identity{}, nil
	}
	if cookie, err := request.Cookie("user_session"); err == nil && cookie.Value != "" {
		session, sessionErr := r.store.GetSession(ctx, cookie.Value)
		if sessionErr != nil {
			return identity{}, &resolverError{code: "SERVER_ERROR", message: "Unable to validate session"}
		}
		if session != nil && session.ExpiresAt.After(time.Now()) {
			user, userErr := r.store.GetUser(ctx, session.UserID)
			if userErr != nil {
				return identity{}, &resolverError{code: "SERVER_ERROR", message: "Unable to validate session"}
			}
			if user != nil {
				return identity{userID: model.UserIDString(user.ID)}, nil
			}
		}
	}
	if cookie, err := request.Cookie("casspeed_owner"); err == nil {
		secret, decodeErr := base64.RawURLEncoding.DecodeString(cookie.Value)
		if decodeErr == nil && len(secret) == 32 {
			hash := sha256.Sum256(secret)
			return identity{ownerHash: hex.EncodeToString(hash[:])}, nil
		}
	}
	return identity{}, nil
}

func validUserTokenFormat(token string) bool {
	if len(token) != len("usr_")+32 || !strings.HasPrefix(token, "usr_") {
		return false
	}
	for _, char := range token[len("usr_"):] {
		if !(char >= '0' && char <= '9' || char >= 'A' && char <= 'Z' || char >= 'a' && char <= 'z') {
			return false
		}
	}
	return true
}

func validUserTokenScope(scope string) bool {
	return scope == "global" || scope == "read-write" || scope == "read"
}

func isNativeAPIRoute(path string) bool {
	return strings.HasPrefix(path, "/api/") || path == "/mcp"
}

func safeSpeedTest(result *model.SpeedTest) *SpeedTestResolver {
	return &SpeedTestResolver{result: SpeedTestResult{
		ID:           graphqlgo.ID(result.ID),
		Timestamp:    result.Timestamp.UTC().Format(time.RFC3339Nano),
		DownloadMbps: result.DownloadMbps,
		UploadMbps:   result.UploadMbps,
		PingMs:       result.PingMs,
		JitterMs:     result.JitterMs,
		PacketLoss:   result.PacketLoss,
	}}
}
