package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/timothy90990/golfitester/scanner"
)

func main() {
	// Define command line flags
	targetURL := flag.String("url", "", "Target URL to test (required)")
	paramsArg := flag.String("params", "", "Comma-separated parameter names to test for LFI vulnerability")
	wordlist := flag.String("wordlist", "", "Path to wordlist file of LFI payloads")
	threads := flag.Int("threads", 10, "Number of concurrent threads")
	timeout := flag.Int("timeout", 10, "Request timeout in seconds")
	verbose := flag.Bool("v", false, "Verbose mode")
	outputFile := flag.String("o", "", "Output file")
	cookies := flag.String("cookies", "", "Cookies to include in requests")
	headers := flag.String("headers", "", "Custom headers (comma-separated)")
	depth := flag.Int("depth", 3, "Traversal depth for path traversal payloads")
	scanAllParams := flag.Bool("scan-all-params", false, "Scan all detectable parameters in the target URL")
	
	// For backward compatibility
	paramName := flag.String("param", "", "Single parameter name to test (use --params for multiple)")
	
	flag.Parse()

	// Check if required flags are provided
	if *targetURL == "" {
		fmt.Println("Error: Target URL is required")
		flag.Usage()
		os.Exit(1)
	}

	// Parse parameters
	var paramsList []string
	if *paramsArg != "" {
		paramsList = strings.Split(*paramsArg, ",")
		// Trim whitespace
		for i, p := range paramsList {
			paramsList[i] = strings.TrimSpace(p)
		}
	} else if *paramName != "" {
		// For backward compatibility
		paramsList = []string{*paramName}
	}

	// Initialize scanner configuration
	config := scanner.Config{
		TargetURL:     *targetURL,
		ParamsList:    paramsList,
		ScanAllParams: *scanAllParams,
		Wordlist:      *wordlist,
		Threads:       *threads,
		Timeout:       *timeout,
		Verbose:       *verbose,
		OutputFile:    *outputFile,
		Cookies:       *cookies,
		Headers:       *headers,
		Depth:         *depth,
	}

	// Create and run scanner
	scanner := scanner.NewScanner(config)
	fmt.Println("Starting LFI vulnerability scan...")
	
	if *verbose {
		if len(paramsList) > 0 {
			fmt.Printf("Testing parameters: %s\n", strings.Join(paramsList, ", "))
		} else if *scanAllParams {
			fmt.Println("Auto-detecting and testing all parameters")
		} else {
			fmt.Println("No parameters specified, will attempt to auto-detect parameters")
		}
	}
	
	results := scanner.Run()

	// Print results summary
	fmt.Printf("\nScan completed!\n")
	fmt.Printf("Total vulnerabilities found: %d\n", len(results))
	
	if len(results) > 0 {
		fmt.Println("\nVulnerable endpoints:")
		for i, result := range results {
			fmt.Printf("%d. %s\n", i+1, result.URL)
			fmt.Printf("   Parameter: %s\n", result.Parameter)
			fmt.Printf("   Payload: %s\n", result.Payload)
			fmt.Printf("   Evidence: %s\n\n", result.Evidence)
		}
	}

	// Save results to output file if specified
	if *outputFile != "" {
		err := scanner.SaveResults(results, *outputFile)
		if err != nil {
			fmt.Printf("Error saving results to file: %s\n", err)
		} else {
			fmt.Printf("Results saved to %s\n", *outputFile)
		}
	}
}