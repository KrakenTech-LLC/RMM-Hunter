package tui

import (
	"fmt"
	"io"

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

type listItem struct {
	title      string
	desc       string
	eliminated bool
}

func (i listItem) Title() string       { return i.title }
func (i listItem) Description() string { return i.desc }
func (i listItem) FilterValue() string { return i.title }

// customDelegate is a custom list item delegate that renders eliminated items in green
type customDelegate struct {
	list.DefaultDelegate
}

func (d customDelegate) Render(w io.Writer, m list.Model, index int, item list.Item) {
	i, ok := item.(listItem)
	if !ok {
		d.DefaultDelegate.Render(w, m, index, item)
		return
	}

	title := i.Title()
	desc := i.Description()

	// Style for eliminated items (green)
	if i.eliminated {
		titleStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("10"))
		descStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("10"))

		if index == m.Index() {
			// Selected item - add background
			titleStyle = titleStyle.Background(lipgloss.Color("240"))
			descStyle = descStyle.Background(lipgloss.Color("240"))
		}

		fmt.Fprintf(w, "%s\n%s", titleStyle.Render("✓ "+title), descStyle.Render("  "+desc))
	} else {
		// Normal rendering for non-eliminated items
		d.DefaultDelegate.Render(w, m, index, item)
	}
}

type ListViewModel struct {
	typeKey    string
	list       list.Model
	header     string
	eliminated map[string]map[int]bool
}

func NewListView(typeKey string, sus suspicious.Suspicious, width, height int, eliminated map[string]map[int]bool) ListViewModel {
	defaultDelegate := list.NewDefaultDelegate()
	defaultDelegate.ShowDescription = true
	delegate := customDelegate{DefaultDelegate: defaultDelegate}
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
		for i, ar := range sus.AutoRuns {
			title := ar.ImageName
			if title == "" {
				title = ar.Entry
			}
			desc := fmt.Sprintf("%s (%s)", ar.ImagePath, ar.Location)
			isEliminated := eliminated[typeKey] != nil && eliminated[typeKey][i]
			items = append(items, listItem{title: title, desc: desc, eliminated: isEliminated})
		}
	case "binaries":
		header = "Suspicious Binaries"
		for i, b := range sus.Binaries {
			isEliminated := eliminated[typeKey] != nil && eliminated[typeKey][i]
			items = append(items, listItem{title: b.Path, desc: "binary file", eliminated: isEliminated})
		}
	case "connections":
		header = "Suspicious Connections"
		for i, c := range sus.OutboundConnections {
			label := fmt.Sprintf("%s -> %s (%s)", c.LocalAddr, c.RemoteAddr, c.RemoteHost)
			isEliminated := eliminated[typeKey] != nil && eliminated[typeKey][i]
			items = append(items, listItem{title: label, desc: fmt.Sprintf("PID %s %s", c.PID, c.Process), eliminated: isEliminated})
		}
	case "directories":
		header = "Suspicious Directories"
		for i, d := range sus.Directories {
			isEliminated := eliminated[typeKey] != nil && eliminated[typeKey][i]
			items = append(items, listItem{title: d.Path, desc: "directory", eliminated: isEliminated})
		}
	case "processes":
		header = "Suspicious Processes"
		for i, p := range sus.Processes {
			label := fmt.Sprintf("%s (PID %d)", p.Name, p.PID)
			desc := p.Path
			isEliminated := eliminated[typeKey] != nil && eliminated[typeKey][i]
			items = append(items, listItem{title: label, desc: desc, eliminated: isEliminated})
		}
	case "scheduledTasks":
		header = "Suspicious Scheduled Tasks"
		for i, t := range sus.ScheduledTasks {
			label := t.Name
			desc := t.Path
			isEliminated := eliminated[typeKey] != nil && eliminated[typeKey][i]
			items = append(items, listItem{title: label, desc: desc, eliminated: isEliminated})
		}
	case "services":
		header = "Suspicious Services"
		for i, s := range sus.Services {
			label := fmt.Sprintf("%s (%s)", s.Name, s.DisplayName)
			desc := s.BinaryPathName
			isEliminated := eliminated[typeKey] != nil && eliminated[typeKey][i]
			items = append(items, listItem{title: label, desc: desc, eliminated: isEliminated})
		}
	}

	l.Title = header + "  —  Left: Back  Enter: Details  q: Quit"
	l.SetItems(items)
	return ListViewModel{typeKey: typeKey, list: l, header: header, eliminated: eliminated}
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
