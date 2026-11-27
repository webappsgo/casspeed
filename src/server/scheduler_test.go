package server

import (
	"context"
	"testing"
	"time"

	"github.com/casapps/casspeed/src/config"
	"github.com/casapps/casspeed/src/server/model"
	"github.com/casapps/casspeed/src/server/store"
)

func TestCleanupSessionsAppliesAnonymousResultRetention(t *testing.T) {
	st, err := store.NewSQLiteStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	ctx := context.Background()
	user := &model.User{ID: 0, Username: "history", Email: "history@example.com", PasswordHash: "hash"}
	if err := st.CreateUser(ctx, user); err != nil {
		t.Fatal(err)
	}
	old := time.Now().UTC().Add(-48 * time.Hour)
	for _, test := range []*model.SpeedTest{
		{ID: "old-anonymous", Timestamp: old, ClientIPHash: "hash"},
		{ID: "recent-anonymous", Timestamp: time.Now().UTC(), ClientIPHash: "hash"},
		{ID: "old-account", UserID: model.UserIDString(user.ID), Timestamp: old, ClientIPHash: "hash"},
	} {
		if err := st.CreateSpeedTest(ctx, test); err != nil {
			t.Fatal(err)
		}
	}
	cfg := config.Default()
	cfg.Test.ResultsRetention = 1
	s := &Server{Config: cfg, Store: st}
	if err := s.cleanupSessions(ctx); err != nil {
		t.Fatal(err)
	}
	for id, wantPresent := range map[string]bool{"old-anonymous": false, "recent-anonymous": true, "old-account": true} {
		got, err := st.GetSpeedTest(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		if (got != nil) != wantPresent {
			t.Errorf("result %q present = %t, want %t", id, got != nil, wantPresent)
		}
	}
}
