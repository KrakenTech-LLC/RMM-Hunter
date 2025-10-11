package suspicious

/*
Suspicious
The object used to resemble the Suspicious artifacts and activities.
*/
type Suspicious struct {
	Artifacts           []Artifact          `json:"artifacts"`
	Persistence         Persistence         `json:"persistence"`
	RootFolder          string              `json:"rootFolder"`
	Binaries            []string            `json:"binaries"`
	Directories         []string            `json:"directories"`
	Services            []*Service          `json:"services"`
	Processes           []Process           `json:"processes"`
	OutboundConnections []NetworkConnection `json:"outboundConnections"`
	AutoRuns            []AutoRun           `json:"autoRuns"`
	ScheduledTasks      []*ScheduledTask    `json:"scheduledTasks"`
}

type NetworkConnection struct {
	LocalAddr  string
	RemoteAddr string
	RemoteHost string
	State      string
	PID        string
	Process    string
}

/*
Artifact
The object used to resemble the artifacts found by the Suspicious software.
*/
type Artifact struct {
	Location string `json:"location"`
	Content  string `json:"content"`
	SHA256   string `json:"sha256"`
}

/*
Persistence
The object used to resemble the persistence methods used by the Suspicious software.
*/
type Persistence struct {
	AutoRuns       []AutoRun       `json:"autoRuns"`
	ScheduledTasks []ScheduledTask `json:"scheduledTasks"`
}

/*
AutoRun
The object used to resemble the auto run methods used by the Suspicious software.
*/
type AutoRun struct {
	Type         string `json:"type"`
	Location     string `json:"location"`
	ImagePath    string `json:"image_path"`
	ImageName    string `json:"image_name"`
	Arguments    string `json:"arguments"`
	MD5          string `json:"md5"`
	SHA1         string `json:"sha1"`
	SHA256       string `json:"sha256"`
	Entry        string `json:"entry"`
	LaunchString string `json:"launch_string"`
}

/*
ScheduledTask
The object used to resemble the scheduled tasks used by the Suspicious software.
*/
type ScheduledTask struct {
	Name         string `json:"name"`
	Author       string `json:"author"`
	CreatedDate  string `json:"createdDate"`
	ModifiedDate string `json:"modifiedDate"`
	Description  string `json:"description"`
	State        string `json:"state"`
	Enabled      bool   `json:"enabled"`
	LastResult   string `json:"lastResult"`
	NextRun      string `json:"nextRun"`
	LastRun      string `json:"lastRun"`
	Path         string `json:"path"`
}

/*
Process
The object used to resemble the processes used by the Suspicious software.
*/
type Process struct {
	Name    string `json:"name"`
	PID     int    `json:"pid"`
	PPID    int    `json:"ppid"`
	Parent  string `json:"parent"`
	Args    string `json:"args"`
	Created string `json:"created"`
	Path    string `json:"path"`
}

/*
Service
The object used to resemble the services used by the Suspicious software.
*/
type Service struct {
	Name             string   `json:"name"`
	DisplayName      string   `json:"displayName"`
	ServiceTypeRaw   uint32   `json:"serviceTypeRaw"`
	ServiceType      string   `json:"serviceType"`
	StartTypeRaw     uint32   `json:"startTypeRaw"`
	StartType        string   `json:"startType"`
	ErrorControlRaw  uint32   `json:"errorControlRaw"`
	ErrorControl     string   `json:"errorControl"`
	BinaryPathName   string   `json:"binaryPathName"`
	LoadOrderGroup   string   `json:"loadOrderGroup"`
	TagId            uint32   `json:"tagId"`
	Dependencies     []string `json:"dependencies"`
	ServiceStartName string   `json:"serviceStartName"`
	Password         string   `json:"password"`
	Description      string   `json:"description"`
	SidType          uint32   `json:"sidType"`
	DelayedAutoStart bool     `json:"delayedAutoStart"`
}
