package enumeration

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// BruteForce attempts to generate subdomains by appending each word in the wordlist to the domain
func BruteForce(domain string, wordlistPath string) []string {
	var subdomains []string

	file, err := os.Open(wordlistPath)
	if err != nil {
		fmt.Printf("Error opening wordlist file: %v\n", err)
		return subdomains
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		word := strings.TrimSpace(scanner.Text())
		if word == "" || strings.HasPrefix(word, "#") {
			continue // Skip empty lines and comments
		}

		subdomain := fmt.Sprintf("%s.%s", word, domain)
		subdomains = append(subdomains, subdomain)
	}

	if err := scanner.Err(); err != nil {
		fmt.Printf("Error reading wordlist file: %v\n", err)
	}

	return subdomains
} 