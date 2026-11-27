package graphql

// Schema is the executable query-only GraphQL schema for the application's
// implemented read API. graphql-go validates it against the concrete resolvers
// when a query handler is constructed.
const Schema = `
"""Public server health, shaped from the same health snapshot as REST."""
type Health {
  project: HealthProject!
  status: String!
  version: String!
  goVersion: String!
  build: HealthBuild!
  uptime: String!
  mode: String!
  timestamp: String!
  cluster: HealthCluster!
  features: HealthFeatures!
  checks: HealthChecks!
  stats: HealthStats!
}

type HealthProject {
  name: String!
  tagline: String!
  description: String!
}

type HealthBuild {
  commit: String!
  date: String!
}

type HealthCluster {
  enabled: Boolean!
  status: String!
}

type HealthFeatures {
  geoip: Boolean!
  tor: HealthTor!
  i2p: HealthI2P!
}

type HealthTor {
  enabled: Boolean!
  running: Boolean!
  status: String!
  hostname: String!
}

type HealthI2P {
  enabled: Boolean!
  running: Boolean!
  state: String!
  status: String!
  hostname: String!
  provider: String!
}

type HealthChecks {
  database: String!
  cache: String!
  disk: String!
  scheduler: String!
  i2p: String!
}

type HealthStats {
  requestsTotal: Int!
  requests24h: Int!
  activeConnections: Int!
}

"""A speed test with only the measurement fields exposed by the REST result API."""
type SpeedTest {
  id: ID!
  timestamp: String!
  downloadMbps: Float!
  uploadMbps: Float!
  pingMs: Float!
  jitterMs: Float!
  packetLoss: Float!
}

"""The authenticated user's own profile fields."""
type UserProfile {
  id: ID!
  username: String!
  email: String!
  emailVerified: Boolean!
  displayName: String!
  bio: String!
  location: String!
  website: String!
  avatarUrl: String!
  timezone: String!
  language: String!
  visibility: String!
  orgVisibility: Boolean!
  shareShowUsername: Boolean!
  createdAt: String!
}

"""The authenticated user's privacy, notification, and appearance settings."""
type UserSettings {
  showEmail: Boolean!
  showActivity: Boolean!
  showOrgs: Boolean!
  searchable: Boolean!
  emailSecurity: Boolean!
  emailSession: Boolean!
  emailMentions: Boolean!
  emailUpdates: Boolean!
  emailNewsletter: Boolean!
  emailDigest: String!
  pushEnabled: Boolean!
  pushMentions: Boolean!
  theme: String!
  fontSize: String!
  reduceMotion: Boolean!
  dateFormat: String!
  timeFormat: String!
}

"""An account-owned device, without credentials or private history."""
type UserDevice {
  id: ID!
  name: String!
  lastSeen: String!
  createdAt: String!
}

"""Safe metadata for an API token; the token itself is never returned."""
type UserToken {
  id: ID!
  tokenPrefix: String!
  name: String!
  scope: String!
  expiresAt: String
  lastUsed: String!
  createdAt: String!
}

type UserSecurity {
  passwordConfigured: Boolean!
  activeSessions: Int!
  passkeys: [UserPasskey!]!
}

type UserPasskey {
  id: ID!
  name: String!
  active: Boolean!
  createdAt: String!
  lastUsed: String
}

type Query {
  """Return the current public health snapshot."""
  health: Health!

  """List the authenticated user's test history; pagination is bounded to 50 records."""
  speedTests(offset: Int = 0): [SpeedTest!]!

  """Read an owned result or an explicitly shared result by its test ID."""
  speedTest(id: ID!): SpeedTest

  """Read the public fields of an explicitly shared result by share code."""
  sharedSpeedTest(code: ID!): SpeedTest

  """Read the authenticated user's own profile."""
  userProfile: UserProfile!

  """Read the authenticated user's own settings."""
  userSettings: UserSettings!

  """Read the authenticated user's non-secret security summary."""
  userSecurity: UserSecurity!

  """List the authenticated user's devices."""
  userDevices: [UserDevice!]!

  """List safe metadata for the authenticated user's API tokens."""
  userTokens: [UserToken!]!
}
`
