package expander

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
)

// Common prefixes and suffixes for permutation
var (
	commonPrefixes = []string{
		"dev", "test", "staging", "stg", "prod", "api", "admin", "internal",
		"stage", "app", "portal", "beta", "qa", "lab", "labs", "sandbox",
	}

	commonSuffixes = []string{
		"2", "01", "02", "03", "1", "3", "-test", "-prod", "-dev", "-api",
		"-admin", "-internal", "-portal", "-app", "-v1", "-v2", "-sandbox",
	}

	joiners = []string{
		".", "-", "_",
	}
)

// ExpandOptions contains configuration for wordlist expansion
type ExpandOptions struct {
	PassiveSubdomains []string
	CommonspeakPath   string
	UseDNSTwist       bool
	VerboseOutput     bool
}

// ExpandWordlist takes a list of passive subdomains and expands it with smart permutations
func ExpandWordlist(options ExpandOptions) []string {
	var expandedList []string
	var uniqueMap = make(map[string]bool)
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Extract prefixes from passive subdomains
	prefixes := extractPrefixes(options.PassiveSubdomains)
	
	if options.VerboseOutput {
		fmt.Println("🧩 Extracted prefixes:", strings.Join(prefixes, ", "))
	}

	// Add base subdomains
	for _, subdomain := range options.PassiveSubdomains {
		uniqueMap[subdomain] = true
	}

	// Generate permutations based on extracted prefixes
	wg.Add(1)
	go func() {
		defer wg.Done()
		perms := generatePermutations(prefixes)
		mu.Lock()
		for _, p := range perms {
			if !uniqueMap[p] {
				uniqueMap[p] = true
				expandedList = append(expandedList, p)
			}
		}
		mu.Unlock()
		
		if options.VerboseOutput {
			fmt.Printf("🔄 Generated %d permutations from prefixes\n", len(perms))
		}
	}()

	// Import from Commonspeak2 if path is provided
	if options.CommonspeakPath != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			commons := importCommonspeak(options.CommonspeakPath)
			mu.Lock()
			for _, c := range commons {
				if !uniqueMap[c] {
					uniqueMap[c] = true
					expandedList = append(expandedList, c)
				}
			}
			mu.Unlock()
			
			if options.VerboseOutput {
				fmt.Printf("📚 Imported %d entries from Commonspeak2\n", len(commons))
			}
		}()
	}

	// Generate DNS twist variations if enabled
	if options.UseDNSTwist {
		wg.Add(1)
		go func() {
			defer wg.Done()
			twists := generateDNSTwist(options.PassiveSubdomains)
			mu.Lock()
			for _, t := range twists {
				if !uniqueMap[t] {
					uniqueMap[t] = true
					expandedList = append(expandedList, t)
				}
			}
			mu.Unlock()
			
			if options.VerboseOutput {
				fmt.Printf("🔤 Generated %d variations using DNSTwist patterns\n", len(twists))
			}
		}()
	}

	wg.Wait()

	// Add the original passive subdomains to the result list
	for subdomain := range uniqueMap {
		expandedList = append(expandedList, subdomain)
	}

	return expandedList
}

// extractPrefixes extracts unique subdomain prefixes from a list of subdomains
func extractPrefixes(subdomains []string) []string {
	prefixMap := make(map[string]bool)

	for _, subdomain := range subdomains {
		// Split the subdomain by dots
		parts := strings.Split(subdomain, ".")
		
		// Skip TLD and domain name, only use subdomains
		if len(parts) <= 2 {
			continue
		}
		
		// Extract each prefix part
		for i := 0; i < len(parts)-2; i++ {
			prefix := parts[i]
			if prefix != "" && !prefixMap[prefix] {
				prefixMap[prefix] = true
			}
		}
	}

	// Convert map to slice
	var prefixes []string
	for prefix := range prefixMap {
		prefixes = append(prefixes, prefix)
	}

	return prefixes
}

// generatePermutations creates new subdomain variations using the extracted prefixes
func generatePermutations(prefixes []string) []string {
	var permutations []string

	// Combine prefixes with common elements
	allPrefixes := append(prefixes, commonPrefixes...)
	
	// Deduplicate
	prefixMap := make(map[string]bool)
	for _, p := range allPrefixes {
		prefixMap[p] = true
	}

	// Convert back to slice
	allPrefixes = []string{}
	for p := range prefixMap {
		allPrefixes = append(allPrefixes, p)
	}

	// Generate permutations
	for _, prefix := range allPrefixes {
		// Basic prefix variations
		permutations = append(permutations, prefix)
		
		// Combine with numbers
		for i := 1; i <= 3; i++ {
			permutations = append(permutations, fmt.Sprintf("%s%d", prefix, i))
		}
		
		// Combine with suffixes
		for _, suffix := range commonSuffixes {
			permutations = append(permutations, prefix+suffix)
		}
		
		// Combine with other prefixes
		for _, otherPrefix := range allPrefixes {
			if prefix == otherPrefix {
				continue
			}
			
			for _, joiner := range joiners {
				permutations = append(permutations, prefix+joiner+otherPrefix)
			}
		}
	}

	return permutations
}

// importCommonspeak imports subdomains from the Commonspeak2 wordlist
func importCommonspeak(commonspeakPath string) []string {
	var wordlist []string

	// Check if the path exists
	if _, err := os.Stat(commonspeakPath); os.IsNotExist(err) {
		// Try to clone or pull the repo
		gitPath := filepath.Dir(commonspeakPath)
		if _, err := os.Stat(gitPath); os.IsNotExist(err) {
			// Clone the repo
			cmd := exec.Command("git", "clone", "https://github.com/assetnote/commonspeak2", gitPath)
			cmd.Run()
		} else {
			// Pull latest changes
			cmd := exec.Command("git", "-C", gitPath, "pull")
			cmd.Run()
		}
	}

	// Try to open the file
	file, err := os.Open(commonspeakPath)
	if err != nil {
		fmt.Printf("Warning: Could not open Commonspeak2 wordlist: %v\n", err)
		return wordlist
	}
	defer file.Close()

	// Read the file line by line
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		word := strings.TrimSpace(scanner.Text())
		if word != "" && !strings.HasPrefix(word, "#") {
			wordlist = append(wordlist, word)
		}
	}

	return wordlist
}

// generateDNSTwist creates variations using common typosquatting patterns
func generateDNSTwist(subdomains []string) []string {
	var variations []string
	
	// Character replacements (for typosquatting)
	replacements := map[rune][]rune{
		'a': {'4', '@'},
		'e': {'3'},
		'i': {'1', '!'},
		'o': {'0'},
		's': {'5', '$'},
		'l': {'1'},
	}
	
	for _, subdomain := range subdomains {
		parts := strings.Split(subdomain, ".")
		
		// Skip if fewer than 2 parts
		if len(parts) < 2 {
			continue
		}
		
		// For each part, generate typo variations
		for i, part := range parts {
			if len(part) < 3 {
				continue // Skip very short parts
			}
			
			// Character substitution
			for j, char := range part {
				if replacements[char] != nil {
					for _, replacement := range replacements[char] {
						newPart := part[:j] + string(replacement) + part[j+1:]
						newParts := make([]string, len(parts))
						copy(newParts, parts)
						newParts[i] = newPart
						variations = append(variations, strings.Join(newParts, "."))
					}
				}
			}
			
			// Character addition (for each position)
			for j := 0; j <= len(part); j++ {
				for _, char := range []rune{'0', '1', '-', '_'} {
					newPart := part[:j] + string(char) + part[j:]
					newParts := make([]string, len(parts))
					copy(newParts, parts)
					newParts[i] = newPart
					variations = append(variations, strings.Join(newParts, "."))
				}
			}
			
			// Character omission (if part is long enough)
			if len(part) > 3 {
				for j := 0; j < len(part); j++ {
					newPart := part[:j] + part[j+1:]
					newParts := make([]string, len(parts))
					copy(newParts, parts)
					newParts[i] = newPart
					variations = append(variations, strings.Join(newParts, "."))
				}
			}
			
			// Character swapping (adjacent chars)
			for j := 0; j < len(part)-1; j++ {
				newPart := part[:j] + string(part[j+1]) + string(part[j]) + part[j+2:]
				newParts := make([]string, len(parts))
				copy(newParts, parts)
				newParts[i] = newPart
				variations = append(variations, strings.Join(newParts, "."))
			}
		}
	}
	
	return variations
} 