package ui

import (
	"argus/fuzzing"
	"argus/scanner"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"
)

type ScanRequest struct {
	Target      string `json:"target"`
	Range       string `json:"range"`
	Concurrency int    `json:"concurrency"`
}

type NmapRequest struct {
	Target string `json:"target"`
	Ports  []int  `json:"ports"`
}

type DomainRequest struct {
	Target string `json:"target"`
	Ports  []int  `json:"ports"`
}

type HostsRequest struct {
	IP     string `json:"ip"`
	Domain string `json:"domain"`
}

type FuzzRequest struct {
	TargetURL  string   `json:"targetUrl"`
	Extensions []string `json:"extensions"`
	Threads    int      `json:"threads"`
}

func StartServer(port int) error {
	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		listener, err = net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return err
		}
	}
	actualPort := listener.Addr().(*net.TCPAddr).Port
	appURL := fmt.Sprintf("http://127.0.0.1:%d", actualPort)

	mux := http.NewServeMux()
	mux.HandleFunc("/", handleIndex)
	mux.HandleFunc("/api/scan", handleScan)
	mux.HandleFunc("/api/nmap", handleNmap)
	mux.HandleFunc("/api/domains", handleDomains)
	mux.HandleFunc("/api/hosts", handleHosts)
	mux.HandleFunc("/api/fuzz", handleFuzz)

	fmt.Printf("[+] Argus Hacker Terminal active at %s\n", appURL)

	go func() {
		time.Sleep(200 * time.Millisecond)
		launchDesktopApp(appURL)
	}()

	return http.Serve(listener, mux)
}

func launchDesktopApp(urlStr string) {
	appCmds := [][]string{
		{"google-chrome", "--app=" + urlStr, "--window-size=1280,850"},
		{"chromium", "--app=" + urlStr, "--window-size=1280,850"},
		{"chromium-browser", "--app=" + urlStr, "--window-size=1280,850"},
		{"firefox", "--new-window", urlStr},
	}

	if runtime.GOOS == "darwin" {
		appCmds = append([][]string{{"open", "-a", "Google Chrome", "--args", "--app=" + urlStr}}, appCmds...)
	} else if runtime.GOOS == "windows" {
		appCmds = append([][]string{{"cmd", "/c", "start", "chrome", "--app=" + urlStr}}, appCmds...)
	}

	for _, cmdArgs := range appCmds {
		if _, err := exec.LookPath(cmdArgs[0]); err == nil {
			cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...)
			if err := cmd.Start(); err == nil {
				return
			}
		}
	}
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	content, err := os.ReadFile("ui/index.html")
	if err != nil {
		content, err = os.ReadFile("index.html")
		if err != nil {
			http.Error(w, "File ui/index.html was not found", http.StatusInternalServerError)
			return
		}
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(content)
}

func handleScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req ScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	startPort, endPort := parsePortRange(req.Range)
	res := scanner.ScanPorts(req.Target, startPort, endPort, req.Concurrency, 500*time.Millisecond, nil)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(res)
}

func handleNmap(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req NmapRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	res := scanner.RunNmapScan(req.Target, req.Ports, nil)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(res)
}

func handleDomains(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req DomainRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	res := scanner.DiscoverDomains(req.Target, req.Ports)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(res)
}

func handleHosts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req HostsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	res := scanner.AddToHosts(req.IP, req.Domain)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(res)
}

func handleFuzz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req FuzzRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	cfg := fuzzing.FuzzConfig{
		TargetURL:  req.TargetURL,
		Extensions: req.Extensions,
		Threads:    req.Threads,
	}

	results, err := fuzzing.StartFuzzing(cfg, nil, nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"results": results,
		"total":   len(results),
	})
}

func parsePortRange(raw string) (int, int) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 1, 1024
	}
	parts := strings.Split(raw, "-")
	if len(parts) == 2 {
		start, e1 := strconv.Atoi(strings.TrimSpace(parts[0]))
		end, e2 := strconv.Atoi(strings.TrimSpace(parts[1]))
		if e1 == nil && e2 == nil && start > 0 && end >= start {
			return start, end
		}
	} else if len(parts) == 1 {
		val, err := strconv.Atoi(parts[0])
		if err == nil && val > 0 {
			return 1, val
		}
	}
	return 1, 1024
}
