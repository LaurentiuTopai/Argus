package scanner

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

type HostsResult struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	Entry   string `json:"entry"`
}

func AddToHosts(ip string, domain string) HostsResult {
	ip = strings.TrimSpace(ip)
	domain = strings.TrimSpace(domain)

	if ip == "" || domain == "" {
		return HostsResult{
			Success: false,
			Message: "IP and domain must be valid",
		}
	}

	entry := fmt.Sprintf("%s %s", ip, domain)

	content, err := os.ReadFile("/etc/hosts")
	if err == nil {
		if strings.Contains(string(content), entry) {
			return HostsResult{
				Success: true,
				Message: fmt.Sprintf("Entry '%s' already exists in /etc/hosts", entry),
				Entry:   entry,
			}
		}
	}

	cmdStr := fmt.Sprintf("echo '%s' | sudo tee -a /etc/hosts", entry)
	cmd := exec.Command("sh", "-c", cmdStr)
	out, err := cmd.CombinedOutput()
	if err != nil {
		f, ferr := os.OpenFile("/etc/hosts", os.O_APPEND|os.O_WRONLY, 0644)
		if ferr == nil {
			defer f.Close()
			_, werr := f.WriteString("\n" + entry + "\n")
			if werr == nil {
				return HostsResult{
					Success: true,
					Message: fmt.Sprintf("Successfully added to /etc/hosts: %s", entry),
					Entry:   entry,
				}
			}
		}

		return HostsResult{
			Success: false,
			Message: fmt.Sprintf("Error adding to /etc/hosts (%v): %s", err, string(out)),
			Entry:   entry,
		}
	}

	return HostsResult{
		Success: true,
		Message: fmt.Sprintf("Successfully added to /etc/hosts (sudo tee): %s", entry),
		Entry:   entry,
	}
}
