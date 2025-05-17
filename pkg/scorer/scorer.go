package scorer

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Cloud provider CNAME patterns
var cloudCnamePatterns = map[string]string{
	`s3[\.-]([a-z0-9-]+\.)?amazonaws\.com`:             "AWS-S3",
	`\.cloudfront\.net`:                                "AWS-CloudFront",
	`\.azure-api\.net`:                                 "Azure-API",
	`\.azurewebsites\.net`:                             "Azure-Web",
	`\.blob\.core\.windows\.net`:                       "Azure-Blob",
	`\.azureedge\.net`:                                 "Azure-CDN",
	`\.googleapis\.com`:                                "Google-API",
	`\.ghs\.googlehosted\.com`:                         "Google-User",
	`\.firebaseapp\.com`:                               "Firebase",
	`\.github\.io`:                                     "GitHub-Pages",
	`\.cloudapp\.net`:                                  "Azure-VM",
	`\.trafficmanager\.net`:                            "Azure-Traffic",
	`\.herokuapp\.com`:                                 "Heroku",
	`\.netlify\.app`:                                   "Netlify",
	`\.pantheonsite\.io`:                               "Pantheon",
	`\.fastly\.net`:                                    "Fastly",
	`\.vercel\.app`:                                    "Vercel",
	`\.shopifyhostedapps\.com`:                         "Shopify",
	`pagecdn\.io`:                                      "PageCDN",
	`\.workers\.dev`:                                   "Cloudflare-Workers",
	`\.appspot\.com`:                                   "Google-AppEngine",
}

// SubdomainInfo represents analysis results for a subdomain
type SubdomainInfo struct {
	Subdomain     string
	HTTPStatus    int
	ContentLength int64
	Headers       map[string]string
	IsTLS         bool
	TLSIssuer     string
	SANs          []string
	CNAMEs        []string
	CloudProvider string
	Score         float64
	Tags          []string
}

// AnalysisOptions holds configuration for analysis
type AnalysisOptions struct {
	Concurrency    int
	Timeout        time.Duration
	VerboseOutput  bool
	ExcludeHeaders bool
}

// DefaultOptions returns a default set of analysis options
func DefaultOptions() AnalysisOptions {
	return AnalysisOptions{
		Concurrency:    10,
		Timeout:        5 * time.Second,
		VerboseOutput:  false,
		ExcludeHeaders: true,
	}
}

// AnalyzeSubdomains performs comprehensive analysis on a list of subdomains
func AnalyzeSubdomains(subdomains []string, options AnalysisOptions) []SubdomainInfo {
	var results []SubdomainInfo
	var mu sync.Mutex
	var wg sync.WaitGroup
	
	// Create a channel for jobs
	jobs := make(chan string, len(subdomains))
	
	// Launch worker goroutines
	for i := 0; i < options.Concurrency; i++ {
		go func() {
			for subdomain := range jobs {
				info := analyzeSubdomain(subdomain, options)
				
				mu.Lock()
				results = append(results, info)
				mu.Unlock()
				
				if options.VerboseOutput {
					tags := ""
					if len(info.Tags) > 0 {
						tags = "[" + strings.Join(info.Tags, "][") + "]"
					}
					fmt.Printf("%s %s (Score: %.1f)\n", tags, info.Subdomain, info.Score)
				}
				
				wg.Done()
			}
		}()
	}
	
	// Send jobs to workers
	for _, subdomain := range subdomains {
		wg.Add(1)
		jobs <- subdomain
	}
	
	// Wait for all jobs to complete
	wg.Wait()
	close(jobs)
	
	// Sort results by score
	sortByScore(results)
	
	return results
}

// analyzeSubdomain performs comprehensive analysis on a single subdomain
func analyzeSubdomain(subdomain string, options AnalysisOptions) SubdomainInfo {
	info := SubdomainInfo{
		Subdomain: subdomain,
		Headers:   make(map[string]string),
		Score:     1.0, // Base score
		Tags:      []string{},
	}

	// HTTP probing
	httpClient := &http.Client{
		Timeout: options.Timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // Skip certificate validation for analysis
			},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Don't follow redirects
		},
	}

	// Try HTTPS first
	httpsURL := fmt.Sprintf("https://%s", subdomain)
	httpsResp, err := httpClient.Get(httpsURL)
	
	if err == nil {
		defer httpsResp.Body.Close()
		info.IsTLS = true
		info.HTTPStatus = httpsResp.StatusCode
		info.ContentLength = httpsResp.ContentLength
		
		// Extract headers
		if !options.ExcludeHeaders {
			for name, values := range httpsResp.Header {
				info.Headers[name] = strings.Join(values, ", ")
			}
		}
		
		// Extract TLS information
		if httpsResp.TLS != nil && len(httpsResp.TLS.PeerCertificates) > 0 {
			cert := httpsResp.TLS.PeerCertificates[0]
			info.TLSIssuer = cert.Issuer.CommonName
			
			// Extract SANs
			for _, san := range cert.DNSNames {
				if san != subdomain {
					info.SANs = append(info.SANs, san)
				}
			}
			
			// Add score for valid cert
			if time.Now().Before(cert.NotAfter) && time.Now().After(cert.NotBefore) {
				info.Score += 0.5
			} else {
				info.Tags = append(info.Tags, "CERT-INVALID")
				info.Score -= 0.3
			}
		}
	} else {
		// Try HTTP if HTTPS fails
		httpURL := fmt.Sprintf("http://%s", subdomain)
		httpResp, err := httpClient.Get(httpURL)
		
		if err == nil {
			defer httpResp.Body.Close()
			info.HTTPStatus = httpResp.StatusCode
			info.ContentLength = httpResp.ContentLength
			
			// Extract headers
			if !options.ExcludeHeaders {
				for name, values := range httpResp.Header {
					info.Headers[name] = strings.Join(values, ", ")
				}
			}
		} else {
			info.HTTPStatus = 0 // Couldn't connect
			info.Tags = append(info.Tags, "NO-HTTP")
		}
	}

	// DNS CNAME lookup
	cnames, err := lookupCNAME(subdomain)
	if err == nil {
		info.CNAMEs = cnames
		
		// Check for cloud provider patterns
		for pattern, provider := range cloudCnamePatterns {
			for _, cname := range cnames {
				matched, _ := regexp.MatchString(pattern, cname)
				if matched {
					info.CloudProvider = provider
					info.Tags = append(info.Tags, provider)
					info.Score += 1.0 // Higher score for cloud endpoints
					break
				}
			}
		}
	}

	// Add tags based on HTTP status
	switch {
	case info.HTTPStatus >= 200 && info.HTTPStatus < 300:
		info.Tags = append(info.Tags, fmt.Sprintf("%d", info.HTTPStatus))
		info.Score += 1.0 // Higher score for 2xx responses
	case info.HTTPStatus >= 300 && info.HTTPStatus < 400:
		info.Tags = append(info.Tags, fmt.Sprintf("%d", info.HTTPStatus))
		info.Tags = append(info.Tags, "REDIRECT")
		info.Score += 0.5 // Medium score for redirects
	case info.HTTPStatus == 403:
		info.Tags = append(info.Tags, "403")
		info.Score += 0.7 // Slightly higher score for 403 (might be interesting)
	case info.HTTPStatus >= 400 && info.HTTPStatus < 500:
		info.Tags = append(info.Tags, fmt.Sprintf("%d", info.HTTPStatus))
		info.Score += 0.2 // Lower score for 4xx responses
	case info.HTTPStatus >= 500:
		info.Tags = append(info.Tags, fmt.Sprintf("%d", info.HTTPStatus))
		info.Score += 0.3 // Lower score for 5xx responses
	}

	// Add tag for content size
	if info.ContentLength > 0 {
		sizeKB := info.ContentLength / 1024
		if sizeKB > 100 {
			info.Tags = append(info.Tags, "LARGE")
			info.Score += 0.2 // Higher score for larger responses
		} else {
			info.Tags = append(info.Tags, fmt.Sprintf("%dKB", sizeKB))
		}
	}

	return info
}

// lookupCNAME performs a DNS CNAME lookup for a subdomain
func lookupCNAME(subdomain string) ([]string, error) {
	var cnames []string
	
	records, err := net.LookupCNAME(subdomain)
	if err != nil {
		return cnames, err
	}
	
	if records != "" {
		cnames = append(cnames, strings.TrimSuffix(records, "."))
		
		// Try to follow CNAME chain
		if cname := cnames[0]; cname != subdomain {
			nestedCnames, _ := lookupCNAME(cname)
			cnames = append(cnames, nestedCnames...)
		}
	}
	
	return cnames, nil
}

// sortByScore sorts the results by their score in descending order
func sortByScore(results []SubdomainInfo) {
	for i := 0; i < len(results); i++ {
		for j := i + 1; j < len(results); j++ {
			if results[i].Score < results[j].Score {
				results[i], results[j] = results[j], results[i]
			}
		}
	}
}

// FormatResults returns a formatted string representation of the analysis results
func FormatResults(results []SubdomainInfo) string {
	var output strings.Builder
	
	for _, info := range results {
		// Format tags
		tags := ""
		if len(info.Tags) > 0 {
			tags = "[" + strings.Join(info.Tags, "][") + "] "
		}
		
		// Format status and information
		status := "?"
		if info.HTTPStatus > 0 {
			status = strconv.Itoa(info.HTTPStatus)
		}
		
		// Format size
		size := ""
		if info.ContentLength > 0 {
			sizeKB := info.ContentLength / 1024
			if sizeKB > 0 {
				size = fmt.Sprintf(" (%d KB)", sizeKB)
			} else {
				size = fmt.Sprintf(" (%d bytes)", info.ContentLength)
			}
		}
		
		// Format additional information
		additional := ""
		if info.CloudProvider != "" {
			additional += fmt.Sprintf(" [Cloud: %s]", info.CloudProvider)
		}
		if len(info.CNAMEs) > 0 {
			additional += fmt.Sprintf(" [CNAME: %s]", info.CNAMEs[0])
		}
		
		line := fmt.Sprintf("%s%s [%s]%s%s\n", tags, info.Subdomain, status, size, additional)
		output.WriteString(line)
	}
	
	return output.String()
} 