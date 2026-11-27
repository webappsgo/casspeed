package main

import "testing"

func TestBuildDateFromEpoch(t *testing.T) {
	tests := []struct {
		name  string
		epoch string
		want  string
	}{
		{name: "valid epoch", epoch: "1765112713", want: "2025-12-07T13:05:13Z"},
		{name: "unset", epoch: "0", want: "N/A"},
		{name: "invalid", epoch: "invalid", want: "N/A"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := buildDateFromEpoch(test.epoch); got != test.want {
				t.Fatalf("buildDateFromEpoch(%q) = %q, want %q", test.epoch, got, test.want)
			}
		})
	}
}
