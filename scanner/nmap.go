package scanner

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"strings"
	"time"
)

type PortDetail struct {
	Port     int    `json:"port"`
	Service  string `json:"service"`
	Banner   string `json:"banner"`
	Protocol string `json:"protocol"`
}

type NmapResult struct {
	Target  string       `json:"target"`
	Details []PortDetail `json:"details"`
	Raw     string       `json:"raw"`
}

func RunNmapScan(target string, openPorts []int, logCb func(line string)) NmapResult {
	if len(openPorts) == 0 {
		return NmapResult{Target: target, Raw: "No open ports found for Nmap inspection."}
	}

	var portStrs []string
	for _, p := range openPorts {
		portStrs = append(portStrs, fmt.Sprintf("%d", p))
	}
	portsArg := strings.Join(portStrs, ",")

	nmapPath, err := exec.LookPath("nmap")
	if err == nil {
		if logCb != nil {
			logCb(fmt.Sprintf("Running nmap -sV -sC -p %s %s ...", portsArg, target))
		}
		cmd := exec.Command(nmapPath, "-sV", "-sC", "-p", portsArg, target)
		var outBuf bytes.Buffer
		stdout, err := cmd.StdoutPipe()
		if err == nil {
			cmd.Start()
			scanner := bufio.NewScanner(stdout)
			for scanner.Scan() {
				line := scanner.Text()
				outBuf.WriteString(line + "\n")
				if logCb != nil {
					logCb(line)
				}
			}
			cmd.Wait()
			return NmapResult{
				Target:  target,
				Details: parseNmapOutput(outBuf.String(), openPorts),
				Raw:     outBuf.String(),
			}
		}
	}

	if logCb != nil {
		logCb("Nmap binary not found in PATH. Running Go fallback service inspection & banner grabbing...")
	}

	var details []PortDetail
	var rawLines []string
	for _, p := range openPorts {
		detail := grabBanner(target, p)
		details = append(details, detail)
		line := fmt.Sprintf("Port %d/tcp: %s - %s", detail.Port, detail.Service, detail.Banner)
		rawLines = append(rawLines, line)
		if logCb != nil {
			logCb(line)
		}
	}

	return NmapResult{
		Target:  target,
		Details: details,
		Raw:     strings.Join(rawLines, "\n"),
	}
}

func grabBanner(target string, port int) PortDetail {
	addr := fmt.Sprintf("%s:%d", target, port)
	service := resolveService(port)

	if port == 80 || port == 443 || port == 8080 || port == 8443 {
		scheme := "http"
		if port == 443 || port == 8443 {
			scheme = "https"
		}
		client := http.Client{Timeout: 2 * time.Second}
		resp, err := client.Get(fmt.Sprintf("%s://%s", scheme, addr))
		if err == nil {
			defer resp.Body.Close()
			server := resp.Header.Get("Server")
			title := ""
			buf := make([]byte, 4096)
			n, _ := resp.Body.Read(buf)
			content := string(buf[:n])
			if idx := strings.Index(strings.ToLower(content), "<title>"); idx != -1 {
				endIdx := strings.Index(strings.ToLower(content[idx:]), "</title>")
				if endIdx != -1 {
					title = strings.TrimSpace(content[idx+7 : idx+endIdx])
				}
			}
			banner := fmt.Sprintf("HTTP Status: %s | Server: %s | Title: %s", resp.Status, server, title)
			return PortDetail{Port: port, Service: service, Banner: banner, Protocol: "tcp"}
		}
	}

	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		return PortDetail{Port: port, Service: service, Banner: "Connection failed", Protocol: "tcp"}
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	banner := ""
	if err == nil && n > 0 {
		banner = strings.TrimSpace(string(buf[:n]))
	} else {
		banner = "Banner undetected (port open)"
	}

	return PortDetail{
		Port:     port,
		Service:  service,
		Banner:   banner,
		Protocol: "tcp",
	}
}

func resolveService(port int) string {
	switch port {
	case 21:
		return "ftp"
	case 22:
		return "ssh"
	case 23:
		return "telnet"
	case 25:
		return "smtp"
	case 53:
		return "domain"
	case 80:
		return "http"
	case 110:
		return "pop3"
	case 143:
		return "imap"
	case 443:
		return "https"
	case 445:
		return "microsoft-ds"
	case 3306:
		return "mysql"
	case 5432:
		return "postgresql"
	case 6379:
		return "redis"
	case 8080:
		return "http-proxy"
	case 8443:
		return "https-alt"
	case 27017:
		return "mongodb"
	default:
		return "unknown"
	}
}

func parseNmapOutput(raw string, openPorts []int) []PortDetail {
	var details []PortDetail
	lines := strings.Split(raw, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "/tcp") && strings.Contains(line, "open") {
			parts := strings.Fields(line)
			if len(parts) >= 3 {
				portStr := strings.Split(parts[0], "/")[0]
				var portVal int
				fmt.Sscanf(portStr, "%d", &portVal)
				service := parts[2]
				banner := ""
				if len(parts) > 3 {
					banner = strings.Join(parts[3:], " ")
				}
				details = append(details, PortDetail{
					Port:     portVal,
					Service:  service,
					Banner:   banner,
					Protocol: "tcp",
				})
			}
		}
	}
	if len(details) == 0 {
		for _, p := range openPorts {
			details = append(details, PortDetail{
				Port:     p,
				Service:  resolveService(p),
				Banner:   "See raw Nmap output",
				Protocol: "tcp",
			})
		}
	}
	return details
}
