package enumeration

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// FetchPassive retrieves subdomains from various passive sources
func FetchPassive(domain string) []string {
	var allSubdomains []string
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Launch goroutines for each source
	wg.Add(3)

	// crt.sh
	go func() {
		defer wg.Done()
		subdomains := fetchFromCrtSh(domain)
		mu.Lock()
		allSubdomains = append(allSubdomains, subdomains...)
		mu.Unlock()
		fmt.Printf("Retrieved %d subdomains from crt.sh\n", len(subdomains))
	}()

	// AlienVault OTX
	go func() {
		defer wg.Done()
		subdomains := fetchFromAlienVault(domain)
		mu.Lock()
		allSubdomains = append(allSubdomains, subdomains...)
		mu.Unlock()
		fmt.Printf("Retrieved %d subdomains from AlienVault OTX\n", len(subdomains))
	}()

	// ThreatCrowd
	go func() {
		defer wg.Done()
		subdomains := fetchFromThreatCrowd(domain)
		mu.Lock()
		allSubdomains = append(allSubdomains, subdomains...)
		mu.Unlock()
		fmt.Printf("Retrieved %d subdomains from ThreatCrowd\n", len(subdomains))
	}()

	// Wait for all fetching to complete
	wg.Wait()

	return allSubdomains
}

// CrtShResult represents a result from crt.sh
type CrtShResult struct {
	NameValue string `json:"name_value"`
}

// fetchFromCrtSh retrieves subdomains from crt.sh
func fetchFromCrtSh(domain string) []string {
	var results []string
	
	client := &http.Client{
		Timeout: 30 * time.Second,
	}
	
	url := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", domain)
	
	resp, err := client.Get(url)
	if err != nil {
		fmt.Printf("Error accessing crt.sh: %v\n", err)
		return results
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		fmt.Printf("Error from crt.sh: HTTP %d\n", resp.StatusCode)
		return results
	}
	
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Error reading response from crt.sh: %v\n", err)
		return results
	}
	
	var crtShResults []CrtShResult
	err = json.Unmarshal(body, &crtShResults)
	if err != nil {
		fmt.Printf("Error parsing JSON from crt.sh: %v\n", err)
		return results
	}
	
	seenSubdomains := make(map[string]bool)
	
	for _, result := range crtShResults {
		// Some entries contain multiple subdomains separated by newlines
		for _, subdomain := range strings.Split(result.NameValue, "\n") {
			subdomain = strings.TrimSpace(subdomain)
			if subdomain != "" && !seenSubdomains[subdomain] {
				seenSubdomains[subdomain] = true
				results = append(results, subdomain)
			}
		}
	}
	
	return results
}

// AlienVaultResult represents a result from the AlienVault OTX API
type AlienVaultResult struct {
	PassiveDNS []struct {
		Hostname string `json:"hostname"`
	} `json:"passive_dns"`
}

// fetchFromAlienVault retrieves subdomains from AlienVault OTX
func fetchFromAlienVault(domain string) []string {
	var results []string
	
	client := &http.Client{
		Timeout: 30 * time.Second,
	}
	
	url := fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/domain/%s/passive_dns", domain)
	
	resp, err := client.Get(url)
	if err != nil {
		fmt.Printf("Error accessing AlienVault OTX: %v\n", err)
		return results
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		fmt.Printf("Error from AlienVault OTX: HTTP %d\n", resp.StatusCode)
		return results
	}
	
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Error reading response from AlienVault OTX: %v\n", err)
		return results
	}
	
	var alienVaultResult AlienVaultResult
	err = json.Unmarshal(body, &alienVaultResult)
	if err != nil {
		fmt.Printf("Error parsing JSON from AlienVault OTX: %v\n", err)
		return results
	}
	
	seenSubdomains := make(map[string]bool)
	
	for _, pdns := range alienVaultResult.PassiveDNS {
		hostname := strings.TrimSpace(pdns.Hostname)
		if hostname != "" && strings.HasSuffix(hostname, domain) && !seenSubdomains[hostname] {
			seenSubdomains[hostname] = true
			results = append(results, hostname)
		}
	}
	
	return results
}

// ThreatCrowdResult represents a result from the ThreatCrowd API
type ThreatCrowdResult struct {
	Subdomains []string `json:"subdomains"`
}

// fetchFromThreatCrowd retrieves subdomains from ThreatCrowd
func fetchFromThreatCrowd(domain string) []string {
	var results []string
	
	// Create a custom transport with TLS configuration that skips verification
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	
	client := &http.Client{
		Timeout:   30 * time.Second,
		Transport: tr,
	}
	
	escapedDomain := url.QueryEscape(domain)
	url := fmt.Sprintf("https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=%s", escapedDomain)
	
	resp, err := client.Get(url)
	if err != nil {
		fmt.Printf("Error accessing ThreatCrowd: %v\n", err)
		return results
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		fmt.Printf("Error from ThreatCrowd: HTTP %d\n", resp.StatusCode)
		return results
	}
	
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Error reading response from ThreatCrowd: %v\n", err)
		return results
	}
	
	var threatCrowdResult ThreatCrowdResult
	err = json.Unmarshal(body, &threatCrowdResult)
	if err != nil {
		fmt.Printf("Error parsing JSON from ThreatCrowd: %v\n", err)
		return results
	}
	
	seenSubdomains := make(map[string]bool)
	
	for _, subdomain := range threatCrowdResult.Subdomains {
		subdomain = strings.TrimSpace(subdomain)
		if subdomain != "" && !seenSubdomains[subdomain] {
			seenSubdomains[subdomain] = true
			results = append(results, subdomain)
		}
	}
	
	return results
} 