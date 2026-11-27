package model

import "testing"

func TestUserIDString(t *testing.T) {
	for _, test := range []struct {
		id   int64
		want string
	}{{0, "0"}, {42, "42"}, {-7, "-7"}} {
		if got := UserIDString(test.id); got != test.want {
			t.Errorf("UserIDString(%d) = %q, want %q", test.id, got, test.want)
		}
	}
}
