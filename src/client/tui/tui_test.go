package tui

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

func TestNewAndInit(t *testing.T) {
	model := New("https://speed.example.com")
	if model.serverURL != "https://speed.example.com" {
		t.Fatalf("serverURL = %q, want configured URL", model.serverURL)
	}
	if cmd := model.Init(); cmd != nil {
		t.Fatalf("Init() = %v, want nil", cmd)
	}
}

func TestUpdateWindowSize(t *testing.T) {
	model := New("http://localhost:64580")
	updated, cmd := model.Update(tea.WindowSizeMsg{Width: 100, Height: 40})
	if cmd != nil {
		t.Fatalf("Update(WindowSizeMsg) command = %v, want nil", cmd)
	}
	got, ok := updated.(Model)
	if !ok {
		t.Fatalf("Update(WindowSizeMsg) returned %T, want Model", updated)
	}
	if got.width != 100 || got.height != 40 {
		t.Errorf("window size = %dx%d, want 100x40", got.width, got.height)
	}
}

func TestUpdateQuitKeys(t *testing.T) {
	for _, key := range []tea.KeyMsg{
		{Type: tea.KeyCtrlC},
		{Type: tea.KeyRunes, Runes: []rune{'q'}},
	} {
		_, cmd := New("http://localhost:64580").Update(key)
		if cmd == nil {
			t.Errorf("Update(%q) command = nil, want quit command", key.String())
		}
	}
}

func TestUpdateUnknownMessage(t *testing.T) {
	model := New("http://localhost:64580")
	updated, cmd := model.Update(struct{}{})
	if cmd != nil {
		t.Fatalf("Update(unknown message) command = %v, want nil", cmd)
	}
	if got, ok := updated.(Model); !ok || got != model {
		t.Errorf("Update(unknown message) = %#v, want unchanged Model", updated)
	}
}

func TestViewDisplaysServerAndHelp(t *testing.T) {
	view := New("https://speed.example.com").View()
	for _, want := range []string{"casspeed - Speed Testing", "Server: https://speed.example.com", "Press 'q' to quit"} {
		if !strings.Contains(view, want) {
			t.Errorf("View() does not contain %q", want)
		}
	}
}
