package cmd

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/omerimzali/subscan/pkg/enumeration"
	"github.com/omerimzali/subscan/pkg/expander"
	"github.com/omerimzali/subscan/pkg/formatter"
	"github.com/omerimzali/subscan/pkg/probe"
	"github.com/omerimzali/subscan/pkg/resolver"
	"github.com/omerimzali/subscan/pkg/scorer"
	"github.com/spf13/cobra"
)

var (
	domain           string
	outputFile       string
	passiveOnly      bool
	activeOnly       bool
	wordlist         string
	smartBruteforce  bool
	commonspeakPath  string
	useDNSTwist      bool
	verboseExpansion bool
	enableScoring    bool
	scoreConcurrency int
	scoreTimeout     int
	verboseScoring   bool
	outputFormat     string
	// Probe related flags
	enableProbe        bool
	probeTimeout       int
	probeConcurrency   int
	probeVerbose       bool
)

var rootCmd = &cobra.Command{
	Use:   "subscan",
	Short: "Subscan - A subdomain enumeration tool",
	Long:  `Subscan is a CLI tool that performs both passive and active subdomain enumeration.`,
	Run: func(cmd *cobra.Command, args []string) {
		if domain == "" {
			fmt.Println("Error: domain is required")
			cmd.Help()
			os.Exit(1)
		}

		// Validate output format if specified
		if outputFormat != "" && !formatter.IsValidFormat(outputFormat) {
			fmt.Printf("Error: invalid output format '%s'. Supported formats: plain, json, csv, html, markdown\n", outputFormat)
			os.Exit(1)
		}

		fmt.Printf("Starting subdomain enumeration for: %s\n", domain)
		
		var passiveResults []string
		var subdomains []string
		
		if !activeOnly {
			fmt.Println("Performing passive enumeration...")
			passiveResults = enumeration.FetchPassive(domain)
			fmt.Printf("Found %d subdomains through passive enumeration\n", len(passiveResults))
			subdomains = append(subdomains, passiveResults...)
		}
		
		var bruteResults []string
		if !passiveOnly {
			var wordlistSubdomains []string
			
			if smartBruteforce && len(passiveResults) > 0 {
				fmt.Println("🧠 Using smart wordlist expansion...")
				
				// Configure expansion options
				options := expander.ExpandOptions{
					PassiveSubdomains: passiveResults,
					CommonspeakPath:   commonspeakPath,
					UseDNSTwist:       useDNSTwist,
					VerboseOutput:     verboseExpansion,
				}
				
				// Run the expansion
				expandedWords := expander.ExpandWordlist(options)
				
				// Append domain to each expanded word to create potential subdomains
				for _, word := range expandedWords {
					if !strings.Contains(word, ".") {
						// It's a prefix, not a full subdomain
						wordlistSubdomains = append(wordlistSubdomains, fmt.Sprintf("%s.%s", word, domain))
					} else {
						// It's already a full subdomain
						wordlistSubdomains = append(wordlistSubdomains, word)
					}
				}
				
				fmt.Printf("🔍 Smart expansion generated %d potential subdomains\n", len(wordlistSubdomains))
			}
			
			// If a traditional wordlist is provided, use it too
			if wordlist != "" {
				fmt.Println("Performing brute force with wordlist...")
				wordlistResults := enumeration.BruteForce(domain, wordlist)
				fmt.Printf("Found %d potential subdomains through wordlist\n", len(wordlistResults))
				
				// Add wordlist results to the brute force candidates
				wordlistSubdomains = append(wordlistSubdomains, wordlistResults...)
			}
			
			// Just adding the results without having done resolution yet
			bruteResults = wordlistSubdomains
			subdomains = append(subdomains, bruteResults...)
		}
		
		// Deduplicate subdomains
		uniqueMap := make(map[string]bool)
		var uniqueSubdomains []string
		
		for _, subdomain := range subdomains {
			subdomain = strings.ToLower(strings.TrimSpace(subdomain))
			if subdomain != "" && !uniqueMap[subdomain] {
				uniqueMap[subdomain] = true
				uniqueSubdomains = append(uniqueSubdomains, subdomain)
			}
		}
		
		fmt.Printf("Total unique subdomains found: %d\n", len(uniqueSubdomains))
		
		fmt.Println("Resolving subdomains...")
		aliveSubdomains := resolver.ResolveSubdomains(uniqueSubdomains)
		fmt.Printf("Found %d alive subdomains\n", len(aliveSubdomains))
		
		// Always score if format other than plain is requested
		if !enableScoring && outputFormat != "" && outputFormat != formatter.FormatPlain {
			enableScoring = true
		}
		
		// Probing for misconfigurations if enabled
		var probeResults []probe.ProbeResult
		if enableProbe && len(aliveSubdomains) > 0 {
			fmt.Println("🔍 Probing for misconfigurations and security issues...")
			
			// Configure probe options
			options := probe.ProbeOptions{
				Concurrency: probeConcurrency,
				Timeout:     time.Duration(probeTimeout) * time.Second,
				UserAgent:   "Subscan/1.0",
				Verbose:     probeVerbose,
			}
			
			// Run probes
			probeResults = probe.RunProbes(aliveSubdomains, options)
			
			// Display probe summary
			fmt.Println(probe.FormatProbeResults(probeResults, false))
			
			// Write probe results to file if requested
			if outputFile != "" {
				// If format is specified, use the formatter package
				if outputFormat != "" {
					formattedOutput, err := formatter.FormatProbeResults(probeResults, outputFormat)
					if err != nil {
						fmt.Printf("Error formatting probe results: %v\n", err)
					} else {
						err = os.WriteFile(outputFile, []byte(formattedOutput), 0644)
						if err != nil {
							fmt.Printf("Error writing probe results to file: %v\n", err)
						} else {
							fmt.Printf("Probe results saved to %s in %s format\n", outputFile, outputFormat)
						}
					}
				} else {
					// For plain text format, use the probe package's formatter
					formattedOutput := probe.FormatProbeResults(probeResults, true)
					writeFormattedToFile(formattedOutput, outputFile)
				}
			}
		}
		
		// Analyze and score subdomains if enabled
		if enableScoring && len(aliveSubdomains) > 0 && !enableProbe {
			fmt.Println("🔍 Analyzing and scoring alive subdomains...")
			
			// Configure analysis options
			options := scorer.AnalysisOptions{
				Concurrency:    scoreConcurrency,
				Timeout:        time.Duration(scoreTimeout) * time.Second,
				VerboseOutput:  verboseScoring,
				ExcludeHeaders: true,
			}
			
			// Run analysis
			results := scorer.AnalyzeSubdomains(aliveSubdomains, options)
			
			// Format results based on the requested format
			if outputFormat != "" {
				formattedOutput, err := formatter.Format(results, outputFormat, domain)
				if err != nil {
					fmt.Printf("Error formatting results: %v\n", err)
					os.Exit(1)
				}
				
				// Write to file if specified, otherwise print to stdout
				if outputFile != "" {
					err = os.WriteFile(outputFile, []byte(formattedOutput), 0644)
					if err != nil {
						fmt.Printf("Error writing to file: %v\n", err)
						os.Exit(1)
					}
					fmt.Printf("Results saved to %s in %s format\n", outputFile, outputFormat)
				} else {
					fmt.Println(formattedOutput)
				}
			} else {
				// Use default formatting
				fmt.Println("\n📊 Subdomain Analysis Results (Sorted by Score):")
				fmt.Println(scorer.FormatResults(results))
				
				// Write results to file if requested
				if outputFile != "" {
					writeFormattedToFile(scorer.FormatResults(results), outputFile)
				}
			}
		} else if !enableProbe {
			// Output basic results without scoring
			if outputFormat != "" && outputFormat != formatter.FormatPlain {
				fmt.Println("Warning: scoring is required for the requested format. Please use --score flag.")
				os.Exit(1)
			}
			
			for _, sub := range aliveSubdomains {
				fmt.Println(sub)
			}
			
			if outputFile != "" && !enableProbe {
				writeToFile(aliveSubdomains, outputFile)
			}
		}
	},
}

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	// Basic options
	rootCmd.Flags().StringVarP(&domain, "domain", "d", "", "Target domain to scan (e.g., example.com)")
	rootCmd.Flags().StringVarP(&outputFile, "output", "o", "", "Path to output file")
	rootCmd.Flags().BoolVar(&passiveOnly, "passive-only", false, "Only perform passive enumeration")
	rootCmd.Flags().BoolVar(&activeOnly, "active-only", false, "Only perform DNS resolution from wordlist")
	rootCmd.Flags().StringVarP(&wordlist, "wordlist", "w", "", "Path to wordlist for brute-force")
	
	// Smart brute-force options
	rootCmd.Flags().BoolVar(&smartBruteforce, "smart-bruteforce", false, "Enable intelligent wordlist expansion")
	rootCmd.Flags().StringVar(&commonspeakPath, "commonspeak", "", "Path to Commonspeak2 wordlist file")
	rootCmd.Flags().BoolVar(&useDNSTwist, "dnstwist", false, "Generate typo-based variations of discovered subdomains")
	rootCmd.Flags().BoolVar(&verboseExpansion, "verbose-expansion", false, "Show detailed output during wordlist expansion")
	
	// Scoring options
	rootCmd.Flags().BoolVar(&enableScoring, "score", false, "Enable subdomain analysis and scoring")
	rootCmd.Flags().IntVar(&scoreConcurrency, "score-concurrency", 10, "Number of concurrent requests during scoring")
	rootCmd.Flags().IntVar(&scoreTimeout, "score-timeout", 5, "Timeout in seconds for HTTP requests during scoring")
	rootCmd.Flags().BoolVar(&verboseScoring, "verbose-scoring", false, "Show detailed output during scoring")
	
	// Output format options
	rootCmd.Flags().StringVarP(&outputFormat, "format", "f", "", "Output format: plain, json, csv, html, markdown")
	
	// Probe options
	rootCmd.Flags().BoolVar(&enableProbe, "probe", false, "Enable probing for common misconfigurations and security issues")
	rootCmd.Flags().IntVar(&probeTimeout, "probe-timeout", 10, "Timeout in seconds for probe requests")
	rootCmd.Flags().IntVar(&probeConcurrency, "probe-concurrency", 10, "Number of concurrent probes")
	rootCmd.Flags().BoolVar(&probeVerbose, "probe-verbose", false, "Show detailed output during probing")
}

func writeToFile(subdomains []string, filepath string) {
	f, err := os.Create(filepath)
	if err != nil {
		fmt.Printf("Error creating output file: %v\n", err)
		return
	}
	defer f.Close()
	
	for _, subdomain := range subdomains {
		f.WriteString(subdomain + "\n")
	}
	
	fmt.Printf("Results saved to %s\n", filepath)
}

func writeFormattedToFile(content string, filepath string) {
	f, err := os.Create(filepath)
	if err != nil {
		fmt.Printf("Error creating output file: %v\n", err)
		return
	}
	defer f.Close()
	
	f.WriteString(content)
	
	fmt.Printf("Results saved to %s\n", filepath)
} 