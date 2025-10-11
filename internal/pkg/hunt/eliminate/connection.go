package eliminate

import (
	"fmt"

	"github.com/Kraken-OffSec/Scurvy/core/firewall"
)

// EliminateConnection adds an outbound block for the connection to the Windows firewall
func EliminateConnection(dst string) error {
	// Create a new WindowsFirewall instance
	fw, err := firewall.NewWindowsFirewall()
	if err != nil {
		return err
	}

	// Check if firewall is enabled
	if !fw.Enabled() {
		return fmt.Errorf("windows firewall is currently disabled. please enable it and try again")
	}

	// Add a block rule for the destination
	return fw.AddRule(firewall.FirewallRule{
		Name:          fmt.Sprintf("Block Outgoing %s", dst),
		Direction:     "outbound",
		Protocol:      "any",
		LocalPort:     "any",
		RemotePort:    "any",
		LocalAddress:  "",
		RemoteAddress: "",
		Action:        "block",
		Profile:       "",
		Destination:   dst,
		Source:        "",
	})
}
