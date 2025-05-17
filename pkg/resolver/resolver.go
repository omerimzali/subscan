package resolver

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const (
	maxWorkers = 50
)

// ResolveSubdomains performs DNS resolution on a list of subdomains to determine which ones are alive
func ResolveSubdomains(subdomains []string) []string {
	var aliveSubdomains []string
	var mu sync.Mutex
	var wg sync.WaitGroup
	
	// Track progress
	var processed int32
	total := len(subdomains)
	
	// Print initial status
	fmt.Printf("Starting resolution of %d subdomains with %d concurrent workers\n", total, maxWorkers)
	
	// Create a channel for jobs
	jobs := make(chan string, len(subdomains))
	
	// Start progress reporting in the background
	stopProgress := make(chan bool)
	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		
		for {
			select {
			case <-ticker.C:
				current := atomic.LoadInt32(&processed)
				percent := float64(current) / float64(total) * 100
				fmt.Printf("Progress: %d/%d (%.1f%%)\n", current, total, percent)
			case <-stopProgress:
				return
			}
		}
	}()

	// Create workers
	for i := 0; i < maxWorkers; i++ {
		go func() {
			for subdomain := range jobs {
				if isAlive(subdomain) {
					mu.Lock()
					aliveSubdomains = append(aliveSubdomains, subdomain)
					mu.Unlock()
				}
				atomic.AddInt32(&processed, 1)
				wg.Done()
			}
		}()
	}

	// Send jobs to the workers
	for _, subdomain := range subdomains {
		wg.Add(1)
		jobs <- subdomain
	}

	// Wait for all jobs to complete
	wg.Wait()
	close(jobs)
	stopProgress <- true
	
	fmt.Printf("Resolution complete: %d alive out of %d total subdomains\n", len(aliveSubdomains), total)

	return aliveSubdomains
}

// isAlive checks if a subdomain is alive by attempting DNS resolution
func isAlive(subdomain string) bool {
	// Set a timeout for the lookup
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Try method 1: LookupHost with context
	ips, err := net.DefaultResolver.LookupHost(ctx, subdomain)
	if err == nil && len(ips) > 0 {
		fmt.Printf("Resolved %s\n", subdomain)
		return true
	}

	// Try method 2: Simple LookupHost as fallback
	ips2, err := net.LookupHost(subdomain)
	if err == nil && len(ips2) > 0 {
		fmt.Printf("Resolved %s (fallback)\n", subdomain)
		return true
	}

	return false
} 