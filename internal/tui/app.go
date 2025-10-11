package tui

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"rmm-hunter/internal/suspicious"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type screen int

const (
	screenFilePicker screen = iota
	screenTypePicker
	screenList
	screenDetail
	screenError
)

type AppModel struct {
	current  screen
	filePick FilePickerModel
	typePick TypePickerModel
	listView ListViewModel
	detail   DetailViewModel
	err      error
	selected string
	data     suspicious.Suspicious
	width    int
	height   int
}

func NewApp() AppModel {
	return AppModel{
		current:  screenFilePicker,
		filePick: NewFilePicker(),
		typePick: NewTypePicker(),
	}
}

func (m AppModel) Init() tea.Cmd { return m.filePick.Init() }

func (m AppModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	// remember the latest terminal size so we can size new screens
	if ws, ok := msg.(tea.WindowSizeMsg); ok {
		m.width, m.height = ws.Width, ws.Height
	}

	switch m.current {
	case screenFilePicker:
		var cmd tea.Cmd
		var tm tea.Model
		tm, cmd = m.filePick.Update(msg)
		if fp, ok := tm.(FilePickerModel); ok {
			m.filePick = fp
		}
		switch v := msg.(type) {
		case FileSelectedMsg:
			if err := m.loadSelectedFile(v.Path); err != nil {
				m.err = err
				m.current = screenError
				return m, nil
			}
			m.current = screenTypePicker
			return m, nil
		}
		return m, cmd

	case screenTypePicker:
		var cmd tea.Cmd
		var tm tea.Model
		tm, cmd = m.typePick.Update(msg)
		if tp, ok := tm.(TypePickerModel); ok {
			m.typePick = tp
		}
		switch v := msg.(type) {
		case BackMsg:
			m.current = screenFilePicker
			return m, nil
		case SelectedTypeMsg:
			m.selected = v.Type
			m.listView = NewListView(v.Type, m.data, m.width, m.height)
			m.current = screenList
			return m, nil
		}
		return m, cmd

	case screenList:
		var cmd tea.Cmd
		var tm tea.Model
		tm, cmd = m.listView.Update(msg)
		if lv, ok := tm.(ListViewModel); ok {
			m.listView = lv
		}
		switch v := msg.(type) {
		case BackMsg:
			m.current = screenTypePicker
			return m, nil
		case ListSelectedMsg:
			m.detail = NewDetailView(v.TypeKey, v.Index, m.data)
			m.current = screenDetail
			return m, nil
		}
		return m, cmd

	case screenDetail:
		var cmd tea.Cmd
		var tm tea.Model
		tm, cmd = m.detail.Update(msg)
		if dv, ok := tm.(DetailViewModel); ok {
			m.detail = dv
		}
		switch v := msg.(type) {
		case BackMsg:
			m.current = screenList
			return m, nil
		case RequestEliminateMsg:
			if err := m.performEliminate(v.TypeKey, v.Index); err != nil {
				var wb WarnBlock
				if errors.As(err, &wb) {
					m.detail.modalWarn = wb.Error()
				} else {
					m.detail.modalErr = err.Error()
				}
				return m, nil
			}
			// success -> rebuild list and go back
			m.listView = NewListView(m.selected, m.data, m.width, m.height)
			m.current = screenList
			return m, nil
		}
		return m, cmd

	case screenError:
		// Any key quits after error is shown
		if _, ok := msg.(tea.KeyMsg); ok {
			return m, tea.Quit
		}
		return m, nil
	}
	return m, nil
}

func (m AppModel) View() string {
	switch m.current {
	case screenFilePicker:
		return m.filePick.View()
	case screenTypePicker:
		return m.typePick.View()
	case screenList:
		return m.listView.View()
	case screenDetail:
		return m.detail.View()
	case screenError:
		return lipgloss.NewStyle().Foreground(lipgloss.Color("203")).Render(fmt.Sprintf("Failed to load JSON: %v\nPress any key to exit.", m.err))
	default:
		return ""
	}
}

// performEliminate routes to placeholder eliminate functions and mutates data on success
func (m *AppModel) performEliminate(typeKey string, idx int) error {
	switch typeKey {
	case "autoruns":
		ar := m.data.AutoRuns[idx]
		if err := EliminateAutoRun(ar); err != nil {
			return err
		}
		m.data.AutoRuns = append(m.data.AutoRuns[:idx], m.data.AutoRuns[idx+1:]...)
	case "binaries":
		b := m.data.Binaries[idx]
		if err := CheckBinaryBlocked(b, m.data); err != nil {
			return err
		}
		if err := EliminateBinary(b); err != nil {
			return err
		}
		m.data.Binaries = append(m.data.Binaries[:idx], m.data.Binaries[idx+1:]...)
	case "connections":
		c := m.data.OutboundConnections[idx]
		if err := EliminateConnection(c); err != nil {
			return err
		}
		m.data.OutboundConnections = append(m.data.OutboundConnections[:idx], m.data.OutboundConnections[idx+1:]...)
	case "directories":
		d := m.data.Directories[idx]
		if err := CheckDirectoryBlocked(d, m.data); err != nil {
			return err
		}
		if err := EliminateDirectory(d); err != nil {
			return err
		}
		m.data.Directories = append(m.data.Directories[:idx], m.data.Directories[idx+1:]...)
	case "processes":
		p := m.data.Processes[idx]
		if err := EliminateProcess(p); err != nil {
			return err
		}
		m.data.Processes = append(m.data.Processes[:idx], m.data.Processes[idx+1:]...)
	case "scheduledTasks":
		t := m.data.ScheduledTasks[idx]
		if err := EliminateScheduledTask(*t); err != nil {
			return err
		}
		m.data.ScheduledTasks = append(m.data.ScheduledTasks[:idx], m.data.ScheduledTasks[idx+1:]...)
	case "services":
		s := m.data.Services[idx]
		if err := EliminateService(*s); err != nil {
			return err
		}
		m.data.Services = append(m.data.Services[:idx], m.data.Services[idx+1:]...)
	}
	return nil
}

// loadSelectedFile reads the JSON file and populates m.data
func (m *AppModel) loadSelectedFile(path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	// Support both wrapped report (with findings) and bare Suspicious JSON
	var envelope struct {
		Findings json.RawMessage `json:"findings"`
	}
	if err := json.Unmarshal(b, &envelope); err == nil && len(envelope.Findings) > 0 {
		var sus suspicious.Suspicious
		if err := json.Unmarshal(envelope.Findings, &sus); err != nil {
			return err
		}
		m.data = sus
		return nil
	}
	// Try bare suspicious structure
	var sus suspicious.Suspicious
	if err := json.Unmarshal(b, &sus); err != nil {
		return fmt.Errorf("no findings in report")
	}
	m.data = sus
	return nil
}

// RunEliminateUI starts the Bubble Tea program for elimination UI
func RunEliminateUI() error {
	p := tea.NewProgram(NewApp())
	_, err := p.Run()
	return err
}
