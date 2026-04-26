package tui

import (
"fmt"
tea "github.com/charmbracelet/bubbletea"
"github.com/charmbracelet/lipgloss"
)

var (
titleStyle = lipgloss.NewStyle().
Bold(true).
Foreground(lipgloss.Color("#bd93f9")).
MarginBottom(1)

statusStyle = lipgloss.NewStyle().
Foreground(lipgloss.Color("#6272a4"))
)

type Model struct {
serverURL string
width     int
height    int
}

func New(serverURL string) Model {
return Model{
serverURL: serverURL,
}
}

func (m Model) Init() tea.Cmd {
return nil
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
switch msg := msg.(type) {
case tea.KeyMsg:
switch msg.String() {
case "ctrl+c", "q":
return m, tea.Quit
}
case tea.WindowSizeMsg:
m.width = msg.Width
m.height = msg.Height
}
return m, nil
}

func (m Model) View() string {
title := titleStyle.Render("casspeed - Speed Testing")
status := statusStyle.Render(fmt.Sprintf("Server: %s", m.serverURL))
help := statusStyle.Render("Press 'q' to quit")

return fmt.Sprintf("%s\n\n%s\n\n%s\n", title, status, help)
}

func Run(serverURL string) error {
p := tea.NewProgram(New(serverURL))
_, err := p.Run()
return err
}
