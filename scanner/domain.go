package scanner

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

type DomainDiscovery struct {
	IP      string   `json:"ip"`
	Port    int      `json:"port"`
	Domains []string `json:"domains"`
}

func DiscoverDomains(targetIP string, openPorts []int) []DomainDiscovery {
	var results []DomainDiscovery

	var httpPorts []int
	for _, p := range openPorts {
		if p == 80 || p == 443 || p == 8080 || p == 8443 || isLikelyHTTP(targetIP, p) {
			httpPorts = append(httpPorts, p)
		}
	}

	domainMap := make(map[string]bool)

	names, err := net.LookupAddr(targetIP)
	if err == nil {
		for _, name := range names {
			cleanName := strings.TrimSuffix(name, ".")
			if cleanName != "" && !isIP(cleanName) {
				domainMap[cleanName] = true
			}
		}
	}

	for _, port := range httpPorts {
		found := extractDomainsFromHTTP(targetIP, port)
		if len(found) > 0 {
			var unique []string
			for _, d := range found {
				if !domainMap[d] {
					domainMap[d] = true
				}
				unique = append(unique, d)
			}
			results = append(results, DomainDiscovery{
				IP:      targetIP,
				Port:    port,
				Domains: unique,
			})
		}
	}

	if len(domainMap) > 0 && len(results) == 0 {
		var all []string
		for d := range domainMap {
			all = append(all, d)
		}
		results = append(results, DomainDiscovery{
			IP:      targetIP,
			Port:    80,
			Domains: all,
		})
	}

	return results
}

func isLikelyHTTP(ip string, port int) bool {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), 1*time.Second)
	if err != nil {
		return false
	}
	defer conn.Close()
	conn.SetWriteDeadline(time.Now().Add(1 * time.Second))
	conn.Write([]byte("GET / HTTP/1.1\r\nHost: " + ip + "\r\n\r\n"))
	conn.SetReadDeadline(time.Now().Add(1 * time.Second))
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err == nil && n > 0 {
		str := string(buf[:n])
		return strings.HasPrefix(str, "HTTP/") || strings.Contains(str, "HTML") || strings.Contains(str, "<html")
	}
	return false
}

func extractDomainsFromHTTP(ip string, port int) []string {
	seen := make(map[string]bool)

	conf := &tls.Config{
		InsecureSkipVerify: true,
	}
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", fmt.Sprintf("%s:%d", ip, port), conf)
	if err == nil {
		certs := conn.ConnectionState().PeerCertificates
		conn.Close()
		for _, cert := range certs {
			if cert.Subject.CommonName != "" && !isIP(cert.Subject.CommonName) {
				seen[strings.ToLower(cert.Subject.CommonName)] = true
			}
			for _, san := range cert.DNSNames {
				if san != "" && !isIP(san) {
					seen[strings.ToLower(san)] = true
				}
			}
		}
	}

	schemes := []string{"http"}
	if port == 443 || port == 8443 {
		schemes = []string{"https"}
	} else {
		schemes = []string{"http", "https"}
	}

	client := &http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	for _, scheme := range schemes {
		rawURL := fmt.Sprintf("%s://%s:%d", scheme, ip, port)
		resp, err := client.Get(rawURL)
		if err != nil {
			continue
		}

		loc := resp.Header.Get("Location")
		if loc != "" {
			if u, err := url.Parse(loc); err == nil && u.Hostname() != "" && !isIP(u.Hostname()) {
				seen[strings.ToLower(u.Hostname())] = true
			}
		}

		csp := resp.Header.Get("Content-Security-Policy")
		if csp != "" {
			for _, dom := range extractDomainsFromText(csp) {
				seen[dom] = true
			}
		}

		bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		resp.Body.Close()
		if err == nil {
			for _, dom := range extractDomainsFromText(string(bodyBytes)) {
				seen[dom] = true
			}
		}
	}

	var list []string
	for d := range seen {
		d = strings.TrimPrefix(d, "*.")
		if d != "" && strings.Contains(d, ".") && !strings.HasSuffix(d, ".local") {
			list = append(list, d)
		}
	}
	return list
}

func extractDomainsFromText(text string) []string {
	var results []string
	re := regexp.MustCompile(`([a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+[\.[a-zA-Z]{2,}]*)`)
	matches := re.FindAllString(text, -1)
	for _, m := range matches {
		m = strings.ToLower(strings.TrimSpace(m))
		if !isIP(m) && strings.Contains(m, ".") && len(m) < 64 {
			results = append(results, m)
		}
	}
	return results
}

func isIP(str string) bool {
	return net.ParseIP(str) != nil
}
