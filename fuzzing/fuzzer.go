package fuzzing

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type EndpointResult struct {
	URL        string `json:"url"`
	Path       string `json:"path"`
	StatusCode int    `json:"statusCode"`
	Size       int64  `json:"size"`
	Redirect   string `json:"redirect"`
}

type FuzzConfig struct {
	TargetURL      string   `json:"targetUrl"`
	WordlistPath   string   `json:"wordlistPath"`
	CustomWords    []string `json:"customWords"`
	Extensions     []string `json:"extensions"`
	StatusCodes    []int    `json:"statusCodes"`
	Threads        int      `json:"threads"`
	FollowRedirect bool     `json:"followRedirect"`
	TimeoutSec     int      `json:"timeoutSec"`
}

var DefaultWordlist = []string{
	"admin", "api", "login", "dashboard", "robots.txt", ".env", ".git", "uploads",
	"config", "backup", "db", "database", "server-status", "index.php", "index.html",
	"users", "user", "v1", "v2", "swagger", "docs", "test", "dev", "app", "assets",
	"static", "css", "js", "img", "images", "public", "private", "secret", "internal",
	"auth", "register", "logout", "profile", "account", "download", "files", "media",
	"tmp", "temp", "phpinfo.php", "info.php", "console", "portal", "management",
}

func StartFuzzing(cfg FuzzConfig, onResult func(res EndpointResult), onProgress func(scanned int, total int)) ([]EndpointResult, error) {
	if cfg.TargetURL == "" {
		return nil, fmt.Errorf("TargetURL cannot be empty")
	}

	targetBase := strings.TrimRight(cfg.TargetURL, "/")

	if cfg.Threads <= 0 {
		cfg.Threads = 40
	}
	if cfg.TimeoutSec <= 0 {
		cfg.TimeoutSec = 5
	}
	if len(cfg.StatusCodes) == 0 {
		cfg.StatusCodes = []int{200, 204, 301, 302, 307, 401, 403}
	}

	validStatusMap := make(map[int]bool)
	for _, code := range cfg.StatusCodes {
		validStatusMap[code] = true
	}

	words := loadWords(cfg)
	if len(words) == 0 {
		words = DefaultWordlist
	}

	var items []string
	items = append(items, words...)
	if len(cfg.Extensions) > 0 {
		for _, w := range words {
			for _, ext := range cfg.Extensions {
				ext = strings.TrimPrefix(ext, ".")
				if ext == "/" {
					items = append(items, w+"/")
				} else if ext != "" {
					items = append(items, w+"."+ext)
				}
			}
		}
	}

	totalItems := len(items)
	jobsChan := make(chan string, cfg.Threads*2)
	var results []EndpointResult
	var mu sync.Mutex

	var scannedCount int64

	client := &http.Client{
		Timeout: time.Duration(cfg.TimeoutSec) * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	if !cfg.FollowRedirect {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	var wg sync.WaitGroup
	for i := 0; i < cfg.Threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for item := range jobsChan {
				reqURL := fmt.Sprintf("%s/%s", targetBase, strings.TrimPrefix(item, "/"))
				resp, err := client.Get(reqURL)
				currScanned := atomic.AddInt64(&scannedCount, 1)

				if err == nil {
					size := resp.ContentLength
					if size < 0 {
						size = 0
					}
					redirect := resp.Header.Get("Location")
					resp.Body.Close()

					if validStatusMap[resp.StatusCode] {
						res := EndpointResult{
							URL:        reqURL,
							Path:       item,
							StatusCode: resp.StatusCode,
							Size:       size,
							Redirect:   redirect,
						}
						mu.Lock()
						results = append(results, res)
						mu.Unlock()

						if onResult != nil {
							onResult(res)
						}
					}
				}

				if onProgress != nil && currScanned%5 == 0 {
					onProgress(int(currScanned), totalItems)
				}
			}
		}()
	}

	for _, item := range items {
		jobsChan <- item
	}
	close(jobsChan)
	wg.Wait()

	if onProgress != nil {
		onProgress(totalItems, totalItems)
	}

	return results, nil
}

func loadWords(cfg FuzzConfig) []string {
	var words []string
	if len(cfg.CustomWords) > 0 {
		words = append(words, cfg.CustomWords...)
	}

	if cfg.WordlistPath != "" {
		file, err := os.Open(cfg.WordlistPath)
		if err == nil {
			defer file.Close()
			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				text := strings.TrimSpace(scanner.Text())
				if text != "" && !strings.HasPrefix(text, "#") {
					words = append(words, text)
				}
			}
		}
	}
	return words
}

func ParseStatusCodes(raw string) []int {
	var codes []int
	parts := strings.Split(raw, ",")
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if val, err := strconv.Atoi(p); err == nil {
			codes = append(codes, val)
		}
	}
	if len(codes) == 0 {
		return []int{200, 204, 301, 302, 307, 401, 403}
	}
	return codes
}

func ParseExtensions(raw string) []string {
	var exts []string
	parts := strings.Split(raw, ",")
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			exts = append(exts, p)
		}
	}
	return exts
}
