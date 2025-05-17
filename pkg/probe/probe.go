package probe

import (
	"crypto/tls"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// ProbeResult represents the result of probing a subdomain for misconfigurations
type ProbeResult struct {
	Domain           string   `json:"domain"`
	CNAME            string   `json:"cname,omitempty"`
	HTTPStatus       int      `json:"status"`
	ContentLength    int64    `json:"content_length"`
	IsTakeover       bool     `json:"is_takeover"`
	S3Public         bool     `json:"s3_public"`
	S3Private        bool     `json:"s3_private"`
	ExposedFiles     []string `json:"exposed_files,omitempty"`
	RedirectURL      string   `json:"redirect_url,omitempty"`
	OpenRedirect     bool     `json:"open_redirect"`
	Vulnerabilities  []string `json:"vulnerabilities,omitempty"`
	Tags             []string `json:"tags,omitempty"`
}

// ProbeOptions contains configuration for the probing process
type ProbeOptions struct {
	Concurrency int
	Timeout     time.Duration
	UserAgent   string
	Verbose     bool
}

// DefaultProbeOptions returns a default set of probe options
func DefaultProbeOptions() ProbeOptions {
	return ProbeOptions{
		Concurrency: 10,
		Timeout:     10 * time.Second,
		UserAgent:   "Subscan/1.0",
		Verbose:     false,
	}
}

// Known services that can be vulnerable to subdomain takeover
// Reference: https://github.com/EdOverflow/can-i-take-over-xyz
var takeoversignatures = map[string]struct {
	cname   []string
	matches []string
}{
	"AWS/S3":             {[]string{"s3.amazonaws.com", "amazonaws.com.s3", ".s3.amazonaws.com"}, []string{"NoSuchBucket", "The specified bucket does not exist"}},
	"Heroku":             {[]string{"herokuapp.com", "herokuapp"}, []string{"No such app", "Heroku | No such app", "herokucdn.com/error-pages/no-such-app.html"}},
	"GitHub":             {[]string{"github.io"}, []string{"There isn't a GitHub Pages site here", "For root URLs (like http://example.com/) you must provide an index.html file"}},
	"Azure":              {[]string{"azurewebsites.net", "cloudapp.net", "azure-api.net"}, []string{"404 Web Site not found"}},
	"Fastly":             {[]string{"fastly.net"}, []string{"Fastly error: unknown domain", "fastly error"}},
	"Pantheon":           {[]string{"pantheonsite.io"}, []string{"The gods are wise", "404 error unknown site!"}},
	"Shopify":            {[]string{"myshopify.com"}, []string{"Sorry, this shop is currently unavailable"}},
	"Zendesk":            {[]string{"zendesk.com"}, []string{"Help Center Closed"}},
	"Wordpress":          {[]string{"wordpress.com"}, []string{"Do you want to register"}},
	"Acquia":             {[]string{"acquia-sites.com"}, []string{"The site you are looking for could not be found."}},
	"Agile CRM":          {[]string{"cname.agilecrm.com"}, []string{"Sorry, this page is no longer available."}},
	"Bitbucket":          {[]string{"bitbucket.io"}, []string{"Repository not found"}},
	"Campaign Monitor":   {[]string{"createsend.com"}, []string{"Double check the URL"}},
	"DigitalOcean":       {[]string{"digitalocean.com"}, []string{"404 Not Found", "Domain uses DO name servers with no records in DO."}},
	"Ghost":              {[]string{"ghost.io"}, []string{"Domain is not configured", "404 Not Found"}},
	"Strikingly":         {[]string{"s.strikinglydns.com"}, []string{"But if you're looking to build your own website", "406 not acceptable"}},
	"Surge.sh":           {[]string{"surge.sh"}, []string{"project not found"}},
	"Tumblr":             {[]string{"domains.tumblr.com"}, []string{"Whatever you were looking for doesn't currently exist at this address."}},
	"Webflow":            {[]string{"proxy.webflow.com", "proxy-ssl.webflow.com"}, []string{"The page you are looking for doesn't exist or has been moved."}},
	"Vercel":             {[]string{"vercel-dns.com", "vercel.app"}, []string{"The deployment could not be found on Vercel."}},
	"Netlify":            {[]string{"netlify.app", "netlify.com"}, []string{"Not found", "404"}},
}

// Sensitive file paths to check for exposure
var sensitiveFilePaths = []struct {
	path        string
	description string
	contentSigs []string
}{
	{".env", "Environment Variables File", []string{"DB_PASSWORD", "API_KEY", "SECRET"}},
	{"/.env", "Environment Variables File", []string{"DB_PASSWORD", "API_KEY", "SECRET"}},
	{"/.git/config", "Git Config File", []string{"[core]", "repositoryformatversion", "filemode"}},
	{"/config.json", "Configuration File", []string{"password", "secret", "key", "token"}},
	{"/wp-config.php", "WordPress Config", []string{"DB_PASSWORD", "AUTH_KEY"}},
	{"/robots.txt", "Robots.txt File", []string{"Disallow:", "Allow:"}},
	{"/sitemap.xml", "Sitemap", []string{"<urlset", "<url>", "<loc>"}},
	{"/.well-known/security.txt", "Security Policy", []string{"Contact:", "Expires:"}},
	{"/server-status", "Apache Status Page", []string{"Apache Server Status", "Server Version:"}},
	{"/phpinfo.php", "PHP Info", []string{"PHP Version", "PHP Credits"}},
}

// Open redirect path patterns to check
var openRedirectPatterns = []struct {
	pathPattern string
	param       string
}{
	{"/redirect", "url"},
	{"/login", "next"},
	{"/logout", "next"},
	{"/signin", "redirect"},
	{"/auth/callback", "url"},
	{"/go", "url"},
	{"/redirect", "to"},
	{"/", "url"},
	{"/", "redirect_to"},
	{"/", "redirect_uri"},
	{"/", "return_to"},
	{"/", "next"},
	{"/", "redir"},
	{"/", "r"},
}

// RunProbes runs all probes against a list of domains
func RunProbes(domains []string, options ProbeOptions) []ProbeResult {
	results := make([]ProbeResult, 0, len(domains))
	resultsChan := make(chan ProbeResult, len(domains))
	var wg sync.WaitGroup
	
	// Create a rate limiter to control concurrency
	semaphore := make(chan struct{}, options.Concurrency)
	
	// Process all domains
	for _, domain := range domains {
		wg.Add(1)
		
		go func(domain string) {
			defer wg.Done()
			
			// Acquire semaphore
			semaphore <- struct{}{}
			defer func() { <-semaphore }()
			
			// Perform the probe
			result := probeDomain(domain, options)
			resultsChan <- result
			
			if options.Verbose {
				// Print any detected issues
				var issues []string
				if result.IsTakeover {
					issues = append(issues, "Subdomain Takeover")
				}
				if result.S3Public {
					issues = append(issues, "Public S3 Bucket")
				}
				if len(result.ExposedFiles) > 0 {
					issues = append(issues, fmt.Sprintf("Exposed Files: %s", strings.Join(result.ExposedFiles, ", ")))
				}
				if result.OpenRedirect {
					issues = append(issues, fmt.Sprintf("Open Redirect: %s", result.RedirectURL))
				}
				
				if len(issues) > 0 {
					fmt.Printf("🔴 %s: %s\n", domain, strings.Join(issues, ", "))
				} else if options.Verbose {
					fmt.Printf("🟢 %s: No issues found\n", domain)
				}
			}
		}(domain)
	}
	
	// Close the results channel when all goroutines are done
	go func() {
		wg.Wait()
		close(resultsChan)
	}()
	
	// Collect results
	for result := range resultsChan {
		results = append(results, result)
	}
	
	return results
}

// probeDomain performs a comprehensive probe of a single domain
func probeDomain(domain string, options ProbeOptions) ProbeResult {
	result := ProbeResult{
		Domain: domain,
		Tags:   []string{},
	}
	
	// HTTP Client with custom timeout and TLS configuration
	client := &http.Client{
		Timeout: options.Timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // Skip certificate validation for probing
			},
			DisableKeepAlives: true,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Don't follow redirects automatically
			return http.ErrUseLastResponse
		},
	}
	
	// 1. Perform initial HTTP request
	req, err := http.NewRequest("GET", fmt.Sprintf("https://%s", domain), nil)
	if err != nil {
		return result
	}
	
	req.Header.Set("User-Agent", options.UserAgent)
	resp, err := client.Do(req)
	
	var body []byte
	if err == nil {
		defer resp.Body.Close()
		result.HTTPStatus = resp.StatusCode
		result.ContentLength = resp.ContentLength
		
		// Read response body (limited to 10KB to avoid memory issues)
		bodyReader := io.LimitReader(resp.Body, 10*1024)
		body, _ = io.ReadAll(bodyReader)
	} else {
		// Try HTTP if HTTPS fails
		req, err = http.NewRequest("GET", fmt.Sprintf("http://%s", domain), nil)
		if err != nil {
			return result
		}
		
		req.Header.Set("User-Agent", options.UserAgent)
		resp, err = client.Do(req)
		
		if err == nil {
			defer resp.Body.Close()
			result.HTTPStatus = resp.StatusCode
			result.ContentLength = resp.ContentLength
			
			bodyReader := io.LimitReader(resp.Body, 10*1024)
			body, _ = io.ReadAll(bodyReader)
		}
	}
	
	// 2. Get CNAME records
	cnames, err := lookupCNAME(domain)
	if err == nil && len(cnames) > 0 {
		result.CNAME = cnames[0]
	}
	
	// 3. Check for subdomain takeover
	if result.CNAME != "" {
		for provider, signature := range takeoversignatures {
			for _, cnamePattern := range signature.cname {
				if strings.Contains(result.CNAME, cnamePattern) {
					// Found a matching CNAME pattern, now check the response content
					for _, contentPattern := range signature.matches {
						if resp != nil && strings.Contains(string(body), contentPattern) {
							result.IsTakeover = true
							vulnDesc := fmt.Sprintf("Subdomain Takeover (%s)", provider)
							result.Vulnerabilities = append(result.Vulnerabilities, vulnDesc)
							result.Tags = append(result.Tags, "TAKEOVER-CANDIDATE")
							result.Tags = append(result.Tags, provider)
							break
						}
					}
					break
				}
			}
		}
	}
	
	// 4. Check for S3 bucket
	if (result.CNAME != "" && (strings.Contains(result.CNAME, "s3.amazonaws.com") || 
		strings.Contains(result.CNAME, "amazonaws.com"))) || 
		(resp != nil && strings.Contains(string(body), "<ListBucketResult")) {
		
		// Check for S3 bucket status
		if strings.Contains(string(body), "<ListBucketResult") {
			result.S3Public = true
			result.Vulnerabilities = append(result.Vulnerabilities, "Public S3 Bucket")
			result.Tags = append(result.Tags, "PUBLIC-S3")
			
			// Parse bucket contents if available
			var bucketResult struct {
				Contents []struct {
					Key string `xml:"Key"`
				} `xml:"Contents"`
			}
			
			err := xml.Unmarshal(body, &bucketResult)
			if err == nil && len(bucketResult.Contents) > 0 {
				var files []string
				for i, content := range bucketResult.Contents {
					if i >= 5 {
						break // Limit to 5 files to avoid too much output
					}
					files = append(files, content.Key)
				}
				result.ExposedFiles = files
			}
		} else if strings.Contains(string(body), "AccessDenied") {
			result.S3Private = true
			result.Tags = append(result.Tags, "PRIVATE-S3")
		} else if strings.Contains(string(body), "NoSuchBucket") {
			result.Vulnerabilities = append(result.Vulnerabilities, "Unclaimed S3 Bucket")
			result.Tags = append(result.Tags, "UNCLAIMED-S3")
		}
	}
	
	// 5. Check for sensitive files
	for _, filePath := range sensitiveFilePaths {
		// Skip if we already have a large number of vulnerabilities
		if len(result.Vulnerabilities) >= 5 {
			break
		}
		
		fileURL := fmt.Sprintf("https://%s%s", domain, filePath.path)
		req, err := http.NewRequest("GET", fileURL, nil)
		if err != nil {
			continue
		}
		
		req.Header.Set("User-Agent", options.UserAgent)
		fileResp, err := client.Do(req)
		if err != nil {
			continue
		}
		
		if fileResp.StatusCode == 200 {
			defer fileResp.Body.Close()
			fileBody, err := io.ReadAll(io.LimitReader(fileResp.Body, 5*1024))
			if err != nil {
				continue
			}
			
			// Check if the content matches any of the signatures
			for _, sig := range filePath.contentSigs {
				if strings.Contains(string(fileBody), sig) {
					vulnDesc := fmt.Sprintf("Exposed %s", filePath.description)
					result.Vulnerabilities = append(result.Vulnerabilities, vulnDesc)
					tag := "EXPOSED-" + strings.ToUpper(strings.Split(filePath.path, "/")[len(strings.Split(filePath.path, "/"))-1])
					result.Tags = append(result.Tags, tag)
					result.ExposedFiles = append(result.ExposedFiles, filePath.path)
					break
				}
			}
		}
	}
	
	// 6. Check for open redirects
	for _, redirectPattern := range openRedirectPatterns {
		// Skip if we already found a redirect vulnerability
		if result.OpenRedirect {
			break
		}
		
		// Skip if we already have a large number of vulnerabilities
		if len(result.Vulnerabilities) >= 5 {
			break
		}
		
		// Test URL
		testURL := fmt.Sprintf("https://%s%s?%s=https://evil.com", 
			domain, redirectPattern.pathPattern, redirectPattern.param)
		
		req, err := http.NewRequest("GET", testURL, nil)
		if err != nil {
			continue
		}
		
		req.Header.Set("User-Agent", options.UserAgent)
		redirectResp, err := client.Do(req)
		if err != nil {
			continue
		}
		
		defer redirectResp.Body.Close()
		
		// Check if it's a redirect to our evil domain
		if redirectResp.StatusCode >= 300 && redirectResp.StatusCode < 400 {
			location := redirectResp.Header.Get("Location")
			if strings.Contains(location, "evil.com") {
				result.OpenRedirect = true
				result.RedirectURL = testURL
				result.Vulnerabilities = append(result.Vulnerabilities, "Open Redirect")
				result.Tags = append(result.Tags, "OPEN-REDIRECT")
			}
		}
	}
	
	return result
}

// lookupCNAME performs DNS CNAME lookup for a domain
func lookupCNAME(domain string) ([]string, error) {
	var cnames []string
	
	records, err := net.LookupCNAME(domain)
	if err != nil {
		return cnames, err
	}
	
	if records != "" {
		cnames = append(cnames, strings.TrimSuffix(records, "."))
		
		// Follow CNAME chain
		if cname := cnames[0]; cname != domain {
			nestedCnames, _ := lookupCNAME(cname)
			cnames = append(cnames, nestedCnames...)
		}
	}
	
	return cnames, nil
}

// ReadProbeResultsFromFile reads probe results from a file
func ReadProbeResultsFromFile(filename string) ([]ProbeResult, error) {
	file, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	
	var results []ProbeResult
	err = json.Unmarshal(file, &results)
	if err != nil {
		return nil, err
	}
	
	return results, nil
}

// FormatProbeResults formats probe results for terminal output
func FormatProbeResults(results []ProbeResult, includeAll bool) string {
	var builder strings.Builder
	
	// Count statistics
	var takeovers, s3Issues, exposedFiles, openRedirects int
	
	for _, result := range results {
		if result.IsTakeover {
			takeovers++
		}
		if result.S3Public {
			s3Issues++
		}
		if len(result.ExposedFiles) > 0 {
			exposedFiles++
		}
		if result.OpenRedirect {
			openRedirects++
		}
	}
	
	// Add summary
	builder.WriteString(fmt.Sprintf("=== Probe Summary ===\n"))
	builder.WriteString(fmt.Sprintf("Total domains probed: %d\n", len(results)))
	builder.WriteString(fmt.Sprintf("Takeover candidates: %d\n", takeovers))
	builder.WriteString(fmt.Sprintf("S3 bucket issues: %d\n", s3Issues))
	builder.WriteString(fmt.Sprintf("Exposed sensitive files: %d\n", exposedFiles))
	builder.WriteString(fmt.Sprintf("Open redirects: %d\n", openRedirects))
	builder.WriteString("\n=== Vulnerability Details ===\n")
	
	// Add detailed results for vulnerable domains
	for _, result := range results {
		if !includeAll && len(result.Vulnerabilities) == 0 {
			continue // Skip non-vulnerable domains unless includeAll is true
		}
		
		// Format tags
		tags := ""
		if len(result.Tags) > 0 {
			tags = "[" + strings.Join(result.Tags, "][") + "]"
		}
		
		builder.WriteString(fmt.Sprintf("%s %s\n", tags, result.Domain))
		
		if result.CNAME != "" {
			builder.WriteString(fmt.Sprintf("  CNAME: %s\n", result.CNAME))
		}
		
		if len(result.Vulnerabilities) > 0 {
			builder.WriteString("  Vulnerabilities:\n")
			for _, vuln := range result.Vulnerabilities {
				builder.WriteString(fmt.Sprintf("    - %s\n", vuln))
			}
		}
		
		if len(result.ExposedFiles) > 0 {
			builder.WriteString("  Exposed Files:\n")
			for _, file := range result.ExposedFiles {
				builder.WriteString(fmt.Sprintf("    - %s\n", file))
			}
		}
		
		if result.OpenRedirect {
			builder.WriteString(fmt.Sprintf("  Open Redirect URL: %s\n", result.RedirectURL))
		}
		
		builder.WriteString("\n")
	}
	
	return builder.String()
} 