package scanner

import (
	"fmt"
	"net"
	"sort"
	"sync"
	"time"
)

type ScanResult struct {
	Target    string  `json:"target"`
	OpenPorts []int   `json:"openPorts"`
	Duration  float64 `json:"duration"`
}

func ScanPorts(target string, startPort, endPort int, concurrency int, timeout time.Duration, callback func(port int)) ScanResult {
	if concurrency <= 0 {
		concurrency = 500
	}
	if timeout <= 0 {
		timeout = 500 * time.Millisecond
	}
	if startPort < 1 {
		startPort = 1
	}
	if endPort > 65535 || endPort < startPort {
		endPort = 65535
	}

	startTime := time.Now()
	portsChan := make(chan int, concurrency)
	resultsChan := make(chan int, concurrency)

	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for port := range portsChan {
				addr := fmt.Sprintf("%s:%d", target, port)
				conn, err := net.DialTimeout("tcp", addr, timeout)
				if err == nil {
					conn.Close()
					resultsChan <- port
					if callback != nil {
						callback(port)
					}
				}
			}
		}()
	}

	go func() {
		for port := startPort; port <= endPort; port++ {
			portsChan <- port
		}
		close(portsChan)
		wg.Wait()
		close(resultsChan)
	}()

	var openPorts []int
	for port := range resultsChan {
		openPorts = append(openPorts, port)
	}

	sort.Ints(openPorts)
	duration := time.Since(startTime).Seconds()

	return ScanResult{
		Target:    target,
		OpenPorts: openPorts,
		Duration:  duration,
	}
}
