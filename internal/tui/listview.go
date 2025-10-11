package tui

import (
	"fmt"

	"rmm-hunter/internal/suspicious"

	"github.com/charmbracelet/bubbles/list"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// ListSelectedMsg indicates which index/type was selected for detail
type ListSelectedMsg struct {
	TypeKey string
	Index   int
}

type listItem struct{ title, desc string }

func (i listItem) Title() string       { return i.title }
func (i listItem) Description() string { return i.desc }
func (i listItem) FilterValue() string { return i.title }

type ListViewModel struct {
	typeKey string
	list    list.Model
	header  string
	// In the future we can add action status per-item
}

func NewListView(typeKey string, sus suspicious.Suspicious, width, height int) ListViewModel {
	delegate := list.NewDefaultDelegate()
	delegate.ShowDescription = true
	l := list.New([]list.Item{}, delegate, 0, 0)
	if width > 0 && height > 0 {
		l.SetSize(width, height-2)
	} else {
		l.SetSize(80, 20)
	}
	l.Styles.Title = lipgloss.NewStyle().Bold(true)

	header := ""
	var items []list.Item
	switch typeKey {
	case "autoruns":
		header = "Suspicious AutoRuns"
		for _, ar := range sus.AutoRuns {
			title := ar.Name
			desc := fmt.Sprintf("%s (%s)", ar.Command, ar.Location)
			items = append(items, listItem{title: title, desc: desc})
		}
	case "binaries":
		header = "Suspicious Binaries"
		for _, b := range sus.Binaries {
			items = append(items, listItem{title: b, desc: "binary file"})
		}
	case "connections":
		header = "Suspicious Connections"
		for _, c := range sus.OutboundConnections {
			label := fmt.Sprintf("%s -> %s (%s)", c.LocalAddr, c.RemoteAddr, c.RemoteHost)
			items = append(items, listItem{title: label, desc: fmt.Sprintf("PID %s %s", c.PID, c.Process)})
		}
	case "directories":
		header = "Suspicious Directories"
		for _, d := range sus.Directories {
			items = append(items, listItem{title: d, desc: "directory"})
		}
	case "processes":
		header = "Suspicious Processes"
		for _, p := range sus.Processes {
			label := fmt.Sprintf("%s (PID %d)", p.Name, p.PID)
			desc := p.Path
			items = append(items, listItem{title: label, desc: desc})
		}
	case "scheduledTasks":
		header = "Suspicious Scheduled Tasks"
		for _, t := range sus.ScheduledTasks {
			label := t.Name
			desc := t.Path
			items = append(items, listItem{title: label, desc: desc})
		}
	case "services":
		header = "Suspicious Services"
		for _, s := range sus.Services {
			label := fmt.Sprintf("%s (%s)", s.Name, s.DisplayName)
			desc := s.BinaryPathName
			items = append(items, listItem{title: label, desc: desc})
		}
	}

	l.Title = header + "  —  Left: Back  Enter: Details  q: Quit"
	l.SetItems(items)
	return ListViewModel{typeKey: typeKey, list: l, header: header}
}

func (m ListViewModel) Init() tea.Cmd { return nil }

func (m ListViewModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.list.SetSize(msg.Width, msg.Height-2)
	case tea.KeyMsg:
		switch msg.String() {
		case "left":
			return m, func() tea.Msg { return BackMsg{} }
		case "q", "esc", "ctrl+c":
			return m, tea.Quit
		case "enter":
			return m, func() tea.Msg { return ListSelectedMsg{TypeKey: m.typeKey, Index: m.list.Index()} }
		}
	}
	var cmd tea.Cmd
	m.list, cmd = m.list.Update(msg)
	return m, cmd
}

func (m ListViewModel) View() string { return m.list.View() }
