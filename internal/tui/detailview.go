package tui

import (
	"fmt"

	"rmm-hunter/internal/suspicious"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// RequestEliminateMsg is emitted by the detail view when '!' is pressed
type RequestEliminateMsg struct {
	TypeKey string
	Index   int
}

// DeletedMsg is emitted after successful elimination to update lists
type DeletedMsg struct {
	TypeKey string
	Index   int
}

type DetailViewModel struct {
	typeKey string
	index   int
	data    suspicious.Suspicious
	// When modal* != "", show modal and require ESC to dismiss
	modalErr  string
	modalWarn string
}

func NewDetailView(typeKey string, index int, data suspicious.Suspicious) DetailViewModel {
	return DetailViewModel{typeKey: typeKey, index: index, data: data}
}

func (m DetailViewModel) Init() tea.Cmd { return nil }

func (m DetailViewModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch v := msg.(type) {
	case tea.KeyMsg:
		if m.modalErr != "" || m.modalWarn != "" {
			// Modal active: only ESC dismisses
			if v.String() == "esc" {
				m.modalErr = ""
				m.modalWarn = ""
			}
			return m, nil
		}
		switch v.String() {
		case "left":
			return m, func() tea.Msg { return BackMsg{} }
		case "!":
			return m, func() tea.Msg { return RequestEliminateMsg{TypeKey: m.typeKey, Index: m.index} }
		case "q", "esc", "ctrl+c":
			return m, tea.Quit
		}
	}
	return m, nil
}

func (m DetailViewModel) View() string {
	title := lipgloss.NewStyle().Bold(true).Render("Details — press ! to eliminate, Left to go back, q to quit")
	body := m.renderDetails()
	view := title + "\n\n" + body
	if m.modalWarn != "" {
		modal := lipgloss.NewStyle().Padding(1, 2).Foreground(lipgloss.Color("214")).Border(lipgloss.RoundedBorder()).Render("Warning:\n" + m.modalWarn + "\n\nPress ESC to dismiss")
		view += "\n\n" + modal
	}
	if m.modalErr != "" {
		modal := lipgloss.NewStyle().Padding(1, 2).Foreground(lipgloss.Color("203")).Border(lipgloss.RoundedBorder()).Render("Elimination failed:\n" + m.modalErr + "\n\nPress ESC to dismiss")
		view += "\n\n" + modal
	}
	return view
}

func (m DetailViewModel) renderDetails() string {
	switch m.typeKey {
	case "autoruns":
		ar := m.data.AutoRuns[m.index]
		return fmt.Sprintf("Type: %s\nEntry: %s\nLaunch: %s\nLocation: %s\nImage: %s\nArgs: %s\nMD5: %s\nSHA1: %s\nSHA256: %s", ar.Type, ar.Entry, ar.LaunchString, ar.Location, ar.ImagePath, ar.Arguments, ar.MD5, ar.SHA1, ar.SHA256)
	case "binaries":
		b := m.data.Binaries[m.index]
		return fmt.Sprintf("Binary: %s\nAction: delete file", b)
	case "connections":
		c := m.data.OutboundConnections[m.index]
		return fmt.Sprintf("Local: %s\nRemote: %s\nHost: %s\nState: %s\nPID: %s\nProcess: %s\nAction: add firewall block (placeholder)", c.LocalAddr, c.RemoteAddr, c.RemoteHost, c.State, c.PID, c.Process)
	case "directories":
		d := m.data.Directories[m.index]
		return fmt.Sprintf("Directory: %s\nAction: delete recursively", d)
	case "processes":
		p := m.data.Processes[m.index]
		return fmt.Sprintf("Name: %s\nPID: %d\nPPID: %d\nParent: %s\nArgs: %s\nCreated: %s\nPath: %s\nAction: stop then delete (placeholder)", p.Name, p.PID, p.PPID, p.Parent, p.Args, p.Created, p.Path)
	case "scheduledTasks":
		t := m.data.ScheduledTasks[m.index]
		return fmt.Sprintf("Name: %s\nAuthor: %s\nState: %s\nEnabled: %v\nLastResult: %s\nNextRun: %s\nLastRun: %s\nPath: %s\nAction: disable then delete (placeholder)", t.Name, t.Author, t.State, t.Enabled, t.LastResult, t.NextRun, t.LastRun, t.Path)
	case "services":
		s := m.data.Services[m.index]
		return fmt.Sprintf("Name: %s\nDisplay: %s\nType: %s\nStartType: %s\nBinPath: %s\nStartName: %s\nDescription: %s\nAction: stop then delete (placeholder)", s.Name, s.DisplayName, s.ServiceType, s.StartType, s.BinaryPathName, s.ServiceStartName, s.Description)
	}
	return ""
}
