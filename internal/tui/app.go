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
	current    screen
	filePick   FilePickerModel
	typePick   TypePickerModel
	listView   ListViewModel
	detail     DetailViewModel
	err        error
	selected   string
	data       suspicious.Suspicious
	width      int
	height     int
	eliminated map[string]map[int]bool // tracks eliminated items: typeKey -> index -> eliminated
	filePath   string                  // path to the loaded JSON file
}

func NewApp() AppModel {
	return AppModel{
		current:    screenFilePicker,
		filePick:   NewFilePicker(),
		typePick:   NewTypePicker(),
		eliminated: make(map[string]map[int]bool),
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
			m.filePath = v.Path
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
			m.listView = NewListView(v.Type, m.data, m.width, m.height, m.eliminated)
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
			m.detail = NewDetailView(v.TypeKey, v.Index, m.data, m.eliminated)
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
			// Check if already eliminated
			if m.eliminated[v.TypeKey] != nil && m.eliminated[v.TypeKey][v.Index] {
				m.detail.modalWarn = "This item has already been eliminated"
				return m, nil
			}

			if err := m.performEliminate(v.TypeKey, v.Index); err != nil {
				var wb WarnBlock
				if errors.As(err, &wb) {
					m.detail.modalWarn = wb.Error()
				} else {
					m.detail.modalErr = err.Error()
				}
				return m, nil
			}
			// success -> mark as eliminated, save file, and rebuild list
			if m.eliminated[v.TypeKey] == nil {
				m.eliminated[v.TypeKey] = make(map[int]bool)
			}
			m.eliminated[v.TypeKey][v.Index] = true

			// Save the updated data to file
			if err := m.saveDataToFile(); err != nil {
				m.detail.modalErr = fmt.Sprintf("Eliminated successfully but failed to save: %v", err)
				return m, nil
			}

			m.detail = NewDetailView(v.TypeKey, v.Index, m.data, m.eliminated)
			m.listView = NewListView(m.selected, m.data, m.width, m.height, m.eliminated)
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

// performEliminate routes to eliminate functions without removing items from data
func (m *AppModel) performEliminate(typeKey string, idx int) error {
	switch typeKey {
	case "autoruns":
		ar := m.data.AutoRuns[idx]
		if err := EliminateAutoRun(ar); err != nil {
			return err
		}
		m.data.AutoRuns[idx].Eliminated = true
	case "binaries":
		b := m.data.Binaries[idx]
		if err := CheckBinaryBlocked(b.Path, m.data); err != nil {
			return err
		}
		if err := EliminateBinary(b.Path); err != nil {
			return err
		}
		m.data.Binaries[idx].Eliminated = true
	case "connections":
		c := m.data.OutboundConnections[idx]
		if err := EliminateConnection(c); err != nil {
			return err
		}
		m.data.OutboundConnections[idx].Eliminated = true
	case "directories":
		d := m.data.Directories[idx]
		if err := CheckDirectoryBlocked(d.Path, m.data); err != nil {
			return err
		}
		if err := EliminateDirectory(d.Path); err != nil {
			return err
		}
		m.data.Directories[idx].Eliminated = true
	case "processes":
		p := m.data.Processes[idx]
		if err := EliminateProcess(p); err != nil {
			return err
		}
		m.data.Processes[idx].Eliminated = true
	case "scheduledTasks":
		t := m.data.ScheduledTasks[idx]
		if err := EliminateScheduledTask(*t); err != nil {
			return err
		}
		m.data.ScheduledTasks[idx].Eliminated = true
	case "services":
		s := m.data.Services[idx]
		if err := EliminateService(*s); err != nil {
			return err
		}
		m.data.Services[idx].Eliminated = true
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
		m.loadEliminatedState()
		return nil
	}
	// Try bare suspicious structure
	var sus suspicious.Suspicious
	if err := json.Unmarshal(b, &sus); err != nil {
		return fmt.Errorf("no findings in report")
	}
	m.data = sus
	m.loadEliminatedState()
	return nil
}

// loadEliminatedState populates the eliminated map from the data structures
func (m *AppModel) loadEliminatedState() {
	m.eliminated = make(map[string]map[int]bool)

	// Load eliminated autoruns
	for i, ar := range m.data.AutoRuns {
		if ar.Eliminated {
			if m.eliminated["autoruns"] == nil {
				m.eliminated["autoruns"] = make(map[int]bool)
			}
			m.eliminated["autoruns"][i] = true
		}
	}

	// Load eliminated binaries
	for i, b := range m.data.Binaries {
		if b.Eliminated {
			if m.eliminated["binaries"] == nil {
				m.eliminated["binaries"] = make(map[int]bool)
			}
			m.eliminated["binaries"][i] = true
		}
	}

	// Load eliminated connections
	for i, c := range m.data.OutboundConnections {
		if c.Eliminated {
			if m.eliminated["connections"] == nil {
				m.eliminated["connections"] = make(map[int]bool)
			}
			m.eliminated["connections"][i] = true
		}
	}

	// Load eliminated directories
	for i, d := range m.data.Directories {
		if d.Eliminated {
			if m.eliminated["directories"] == nil {
				m.eliminated["directories"] = make(map[int]bool)
			}
			m.eliminated["directories"][i] = true
		}
	}

	// Load eliminated processes
	for i, p := range m.data.Processes {
		if p.Eliminated {
			if m.eliminated["processes"] == nil {
				m.eliminated["processes"] = make(map[int]bool)
			}
			m.eliminated["processes"][i] = true
		}
	}

	// Load eliminated scheduled tasks
	for i, t := range m.data.ScheduledTasks {
		if t.Eliminated {
			if m.eliminated["scheduledTasks"] == nil {
				m.eliminated["scheduledTasks"] = make(map[int]bool)
			}
			m.eliminated["scheduledTasks"][i] = true
		}
	}

	// Load eliminated services
	for i, s := range m.data.Services {
		if s.Eliminated {
			if m.eliminated["services"] == nil {
				m.eliminated["services"] = make(map[int]bool)
			}
			m.eliminated["services"][i] = true
		}
	}
}

// saveDataToFile saves the current data back to the JSON file
func (m *AppModel) saveDataToFile() error {
	if m.filePath == "" {
		return fmt.Errorf("no file path set")
	}

	// Read the original file to determine format
	b, err := os.ReadFile(m.filePath)
	if err != nil {
		return err
	}

	// Check if it's wrapped format
	var envelope struct {
		Findings json.RawMessage `json:"findings"`
	}
	isWrapped := json.Unmarshal(b, &envelope) == nil && len(envelope.Findings) > 0

	var output []byte
	if isWrapped {
		// Re-read the full envelope
		var fullEnvelope map[string]interface{}
		if err := json.Unmarshal(b, &fullEnvelope); err != nil {
			return err
		}

		// Update the findings
		findingsJSON, err := json.MarshalIndent(m.data, "", "  ")
		if err != nil {
			return err
		}
		fullEnvelope["findings"] = json.RawMessage(findingsJSON)

		output, err = json.MarshalIndent(fullEnvelope, "", "  ")
		if err != nil {
			return err
		}
	} else {
		// Bare format
		output, err = json.MarshalIndent(m.data, "", "  ")
		if err != nil {
			return err
		}
	}

	return os.WriteFile(m.filePath, output, 0644)
}

// RunEliminateUI starts the Bubble Tea program for elimination UI
func RunEliminateUI() error {
	p := tea.NewProgram(NewApp())
	_, err := p.Run()
	return err
}
