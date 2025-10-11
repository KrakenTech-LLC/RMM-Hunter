package tui

import (
	"strings"

	"github.com/charmbracelet/bubbles/help"
	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// SelectedTypeMsg is sent when the user chooses a type (1-7)
// Valid Type values: "autoruns", "binaries", "connections", "directories", "processes", "scheduledTasks", "services"
type SelectedTypeMsg struct{ Type string }

// BackMsg is sent when the user presses Left to go back
type BackMsg struct{}

// keyMap defines keybindings for the type picker
// It must satisfy key.Map for the help component
// We only need: 1-7, left/back, help, quit
type keyMap struct {
	Help  key.Binding
	Quit  key.Binding
	Back  key.Binding
	One   key.Binding
	Two   key.Binding
	Three key.Binding
	Four  key.Binding
	Five  key.Binding
	Six   key.Binding
	Seven key.Binding
}

func (k keyMap) ShortHelp() []key.Binding {
	return []key.Binding{k.Back, k.Help, k.Quit}
}

func (k keyMap) FullHelp() [][]key.Binding {
	return [][]key.Binding{
		{k.One, k.Two, k.Three, k.Four, k.Five, k.Six, k.Seven},
		{k.Back, k.Help, k.Quit},
	}
}

var keys = keyMap{
	One:   key.NewBinding(key.WithKeys("1"), key.WithHelp("1", "AutoRuns")),
	Two:   key.NewBinding(key.WithKeys("2"), key.WithHelp("2", "Binaries")),
	Three: key.NewBinding(key.WithKeys("3"), key.WithHelp("3", "Connections")),
	Four:  key.NewBinding(key.WithKeys("4"), key.WithHelp("4", "Directories")),
	Five:  key.NewBinding(key.WithKeys("5"), key.WithHelp("5", "Processes")),
	Six:   key.NewBinding(key.WithKeys("6"), key.WithHelp("6", "Scheduled Tasks")),
	Seven: key.NewBinding(key.WithKeys("7"), key.WithHelp("7", "Services")),
	Back:  key.NewBinding(key.WithKeys("left"), key.WithHelp("←", "back")),
	Help:  key.NewBinding(key.WithKeys("?"), key.WithHelp("?", "toggle help")),
	Quit:  key.NewBinding(key.WithKeys("q", "esc", "ctrl+c"), key.WithHelp("q", "quit")),
}

type TypePickerModel struct {
	keys       keyMap
	help       help.Model
	inputStyle lipgloss.Style
	quitting   bool
}

func NewTypePicker() TypePickerModel {
	return TypePickerModel{
		keys:       keys,
		help:       help.New(),
		inputStyle: lipgloss.NewStyle().Foreground(lipgloss.Color("#ef8430")),
	}
}

func (m TypePickerModel) Init() tea.Cmd { return nil }

func (m TypePickerModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.help.Width = msg.Width
	case tea.KeyMsg:
		switch {
		case key.Matches(msg, m.keys.Quit):
			m.quitting = true
			return m, tea.Quit
		case key.Matches(msg, m.keys.Help):
			m.help.ShowAll = !m.help.ShowAll
		case key.Matches(msg, m.keys.Back):
			return m, func() tea.Msg { return BackMsg{} }
		case key.Matches(msg, m.keys.One):
			return m, func() tea.Msg { return SelectedTypeMsg{Type: "autoruns"} }
		case key.Matches(msg, m.keys.Two):
			return m, func() tea.Msg { return SelectedTypeMsg{Type: "binaries"} }
		case key.Matches(msg, m.keys.Three):
			return m, func() tea.Msg { return SelectedTypeMsg{Type: "connections"} }
		case key.Matches(msg, m.keys.Four):
			return m, func() tea.Msg { return SelectedTypeMsg{Type: "directories"} }
		case key.Matches(msg, m.keys.Five):
			return m, func() tea.Msg { return SelectedTypeMsg{Type: "processes"} }
		case key.Matches(msg, m.keys.Six):
			return m, func() tea.Msg { return SelectedTypeMsg{Type: "scheduledTasks"} }
		case key.Matches(msg, m.keys.Seven):
			return m, func() tea.Msg { return SelectedTypeMsg{Type: "services"} }
		}
	}
	return m, nil
}

func (m TypePickerModel) View() string {
	if m.quitting {
		return "Bye!\n"
	}
	title := lipgloss.NewStyle().Bold(true).Render("Select a type to manage")
	menu := "\n  1) AutoRuns\n  2) Binaries\n  3) Connections\n  4) Directories\n  5) Processes\n  6) Scheduled Tasks\n  7) Services\n"
	helpView := m.help.View(m.keys)
	height := 8 - strings.Count(menu, "\n") - strings.Count(helpView, "\n")
	if height < 0 {
		height = 0
	}
	return title + "\n" + menu + strings.Repeat("\n", height) + helpView
}
