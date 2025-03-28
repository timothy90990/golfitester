package main

import (
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/timothy90990/golfitester/scanner"
)

// ANSI color codes for output
const (
	colorReset   = "\033[0m"
	colorRed     = "\033[31m"
	colorGreen   = "\033[32m"
	colorYellow  = "\033[33m"
	colorBlue    = "\033[34m"
	colorMagenta = "\033[35m"
	colorCyan    = "\033[36m"
	colorWhite   = "\033[37m"
	colorBold    = "\033[1m"
)

func main() {
	// Create a custom flag set for better help output
	flagSet := flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	flagSet.Usage = func() {
		fmt.Fprintf(os.Stderr, "%sGoLFITester - A Local File Inclusion vulnerability scanner%s\n\n", colorBold, colorReset)
		fmt.Fprintf(os.Stderr, "Usage: %s [options]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "%sOptions:%s\n", colorBold, colorReset)
		fmt.Fprintf(os.Stderr, "  -u, --url string          Target URL to test (required if not using -r)\n")
		fmt.Fprintf(os.Stderr, "  -p, --param string        Parameter(s) to test - comma-separated for multiple\n")
		fmt.Fprintf(os.Stderr, "  -a, --scan-all-params     Scan all detectable parameters in the URL\n")
		fmt.Fprintf(os.Stderr, "  -w, --wordlist string     Path to wordlist file of LFI payloads\n")
		fmt.Fprintf(os.Stderr, "  -t, --threads int         Number of concurrent threads (default: 10)\n")
		fmt.Fprintf(os.Stderr, "  -to, --timeout int        Request timeout in seconds (default: 10)\n")
		fmt.Fprintf(os.Stderr, "  -v, --verbose             Verbose mode\n")
		fmt.Fprintf(os.Stderr, "  -o, --output string       Output file to save results\n")
		fmt.Fprintf(os.Stderr, "  -c, --cookies string      Cookies to include in requests\n")
		fmt.Fprintf(os.Stderr, "  -H, --headers string      Custom headers (comma-separated)\n")
		fmt.Fprintf(os.Stderr, "  -d, --depth int           Traversal depth for path traversal payloads (default: 3)\n")
		fmt.Fprintf(os.Stderr, "  -r, --request string      Path to a file containing a HTTP request\n")
		fmt.Fprintf(os.Stderr, "  -i, --ignore string       Comma-separated signatures to ignore (to filter out false positives)\n")
		fmt.Fprintf(os.Stderr, "  -h, --help                Display this help message\n")
		
		fmt.Fprintf(os.Stderr, "\n%sExamples:%s\n", colorBold, colorReset)
		fmt.Fprintf(os.Stderr, "  %s -u \"http://example.com/page.php?file=test\"\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -u \"http://example.com/page.php\" -p \"file,include\"\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -r \"burp_request.txt\" -p \"file\"\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -u \"http://example.com/page.php?file=test\" -i \"root:x:,nobody:x:\"\n", os.Args[0])
	}

	// Define command line flags with short and long versions
	// We'll manually parse them with a custom parser
	if len(os.Args) == 1 || (len(os.Args) > 1 && (os.Args[1] == "-h" || os.Args[1] == "--help")) {
		flagSet.Usage()
		os.Exit(0)
	}

	// Initialize variables for flags
	var targetURL, params, wordlist, outputFile, cookies, headers, requestFile, ignoreSignatures string
	var threads, timeout, depth int
	var verbose, scanAllParams bool
	
	// Default values
	threads = 10
	timeout = 10
	depth = 3

	// Manual flag parsing to handle both short and long versions
	args := os.Args[1:]
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-u", "--url":
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				targetURL = args[i+1]
				i++
			}
		case "-p", "--param":
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				params = args[i+1]
				i++
			}
		case "-w", "--wordlist":
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				wordlist = args[i+1]
				i++
			}
		case "-t", "--threads":
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				fmt.Sscanf(args[i+1], "%d", &threads)
				i++
			}
		case "-to", "--timeout":
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				fmt.Sscanf(args[i+1], "%d", &timeout)
				i++
			}
		case "-v", "--verbose":
			verbose = true
		case "-o", "--output":
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				outputFile = args[i+1]
				i++
			}
		case "-c", "--cookies":
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				cookies = args[i+1]
				i++
			}
		case "-H", "--headers":
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				headers = args[i+1]
				i++
			}
		case "-d", "--depth":
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				fmt.Sscanf(args[i+1], "%d", &depth)
				i++
			}
		case "-a", "--scan-all-params":
			scanAllParams = true
		case "-r", "--request":
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				requestFile = args[i+1]
				i++
			}
		case "-i", "--ignore":
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				ignoreSignatures = args[i+1]
				i++
			}
		default:
			if strings.HasPrefix(args[i], "-") {
				fmt.Printf("%sUnknown option: %s%s\n", colorRed, args[i], colorReset)
				flagSet.Usage()
				os.Exit(1)
			}
		}
	}

	// Check if required flags are provided
	if targetURL == "" && requestFile == "" {
		fmt.Printf("%sError: Either Target URL or Request file is required%s\n", colorRed, colorReset)
		flagSet.Usage()
		os.Exit(1)
	}

	// Parse parameters
	var paramsList []string
	if params != "" {
		paramsList = strings.Split(params, ",")
		// Trim whitespace
		for i, p := range paramsList {
			paramsList[i] = strings.TrimSpace(p)
		}
	}

	// Parse ignore signatures if provided
	var ignoreSignaturesList []string
	if ignoreSignatures != "" {
		ignoreSignaturesList = strings.Split(ignoreSignatures, ",")
		// Trim whitespace
		for i, sig := range ignoreSignaturesList {
			ignoreSignaturesList[i] = strings.TrimSpace(sig)
		}
	}

	// Initialize scanner configuration
	config := scanner.Config{
		TargetURL:        targetURL,
		ParamsList:       paramsList,
		ScanAllParams:    scanAllParams,
		Wordlist:         wordlist,
		Threads:          threads,
		Timeout:          timeout,
		Verbose:          verbose,
		OutputFile:       outputFile,
		Cookies:          cookies,
		Headers:          headers,
		Depth:            depth,
		RequestFile:      requestFile,
		IgnoreSignatures: ignoreSignaturesList,
	}

	// Create and run scanner
	scannerInstance := scanner.NewScanner(config)
	fmt.Printf("%sStarting LFI vulnerability scan...%s\n", colorCyan, colorReset)
	
	if verbose {
		if requestFile != "" {
			fmt.Printf("Using request from file: %s\n", requestFile)
			if len(paramsList) > 0 {
				fmt.Printf("Testing parameters: %s\n", strings.Join(paramsList, ", "))
			} else {
				fmt.Println("No specific parameters specified, will attempt to auto-detect parameters")
			}
		} else if len(paramsList) > 0 {
			fmt.Printf("Testing parameters: %s\n", strings.Join(paramsList, ", "))
		} else if scanAllParams {
			fmt.Println("Auto-detecting and testing all parameters")
		} else {
			fmt.Println("No parameters specified, will attempt to auto-detect parameters")
		}
		
		if len(ignoreSignaturesList) > 0 {
			fmt.Printf("Ignoring signatures: %s\n", strings.Join(ignoreSignaturesList, ", "))
		}
	}
	
	results := scannerInstance.Run()
	
	// Explicitly close all idle connections after scan completes
	scannerInstance.CloseIdleConnections()

	// Print results summary
	fmt.Printf("\n%sScan completed!%s\n", colorGreen, colorReset)
	
	// Print HTTP status code statistics
	printStatusCodeStatistics(scannerInstance)
	
	// Check for potential false positives
	successCountsByParam := make(map[string]int)
	
	// Count successful payloads per parameter
	for _, result := range results {
		successCountsByParam[result.Parameter]++
	}
	
	// Get total payload count per parameter (estimated from status counts)
	statusCounts := scannerInstance.GetStatusCounts()
	totalRequests := 0
	for _, count := range statusCounts {
		totalRequests += count
	}
	
	// If we have parameters to test
	if len(paramsList) > 0 {
		// Estimate payloads per parameter (assuming equal distribution)
		payloadsPerParam := totalRequests / len(paramsList)
		
		// Check for parameters with high success rates (potential false positives)
		for param, successCount := range successCountsByParam {
			// If nearly all payloads are "successful" for this parameter (>90%)
			if successCount > (payloadsPerParam * 90 / 100) {
				fmt.Printf("\n%sWARNING: Parameter '%s' shows success for %d/%d payloads (%.1f%%)%s\n", 
					colorYellow, param, successCount, payloadsPerParam, 
					float64(successCount)/float64(payloadsPerParam)*100, colorReset)
				fmt.Printf("  This may indicate false positives. Check results carefully or use -i to ignore specific signatures.\n")
			}
		}
	}
	
	fmt.Printf("%sTotal vulnerabilities found: %s%d%s\n", colorBold, colorGreen, len(results), colorReset)
	
	if len(results) > 0 {
		fmt.Printf("\n%sVulnerable endpoints:%s\n", colorYellow, colorReset)
		for i, result := range results {
			// Get color for status code
			statusColor := getStatusCodeColor(result.StatusCode)
			
			fmt.Printf("%d. %s%s%s\n", i+1, colorGreen, result.URL, colorReset)
			fmt.Printf("   Parameter: %s%s%s\n", colorCyan, result.Parameter, colorReset)
			fmt.Printf("   Payload: %s%s%s\n", colorYellow, result.Payload, colorReset)
			fmt.Printf("   Status Code: %s%d%s\n", statusColor, result.StatusCode, colorReset)
			fmt.Printf("   Content-Type: %s\n", result.ContentType)
			fmt.Printf("   Evidence: %s%s%s\n\n", colorMagenta, result.Evidence, colorReset)
		}
	}

	// Save results to output file if specified
	if outputFile != "" {
		err := scannerInstance.SaveResults(results, outputFile)
		if (err != nil) {
			fmt.Printf("%sError saving results to file: %s%s\n", colorRed, err, colorReset)
		} else {
			fmt.Printf("%sResults saved to %s%s\n", colorGreen, outputFile, colorReset)
		}
	}
}

// getStatusCodeColor returns the color for a given HTTP status code
func getStatusCodeColor(statusCode int) string {
	switch {
	case statusCode >= 200 && statusCode < 300:
		return colorGreen
	case statusCode >= 300 && statusCode < 400:
		return colorYellow
	case statusCode >= 400 && statusCode < 500:
		return colorRed
	case statusCode >= 500:
		return colorMagenta
	default:
		return colorReset
	}
}

// printStatusCodeStatistics prints statistics of HTTP status codes encountered during the scan
func printStatusCodeStatistics(s *scanner.Scanner) {
	// Get status counts from scanner
	statusCounts := s.GetStatusCounts()
	
	if len(statusCounts) == 0 {
		return
	}
	
	// Sort status codes for a consistent output
	var codes []int
	for code := range statusCounts {
		codes = append(codes, code)
	}
	sort.Ints(codes)
	
	fmt.Printf("\n%sHTTP Status Code Summary:%s\n", colorBold, colorReset)
	
	// Count invalid responses (4xx and 5xx)
	var invalidCount int
	for _, code := range codes {
		if code >= 400 {
			invalidCount += statusCounts[code]
		}
	}
	
	// Print counts for each status code
	for _, code := range codes {
		count := statusCounts[code]
		statusColor := getStatusCodeColor(code)
		fmt.Printf("  %s%d%s: %d requests\n", statusColor, code, colorReset, count)
	}
	
	// Print invalid response summary if any found
	if invalidCount > 0 {
		fmt.Printf("\n%sInvalid Responses: %s%d%s requests returned error status codes (4xx, 5xx)%s\n", 
			colorBold, colorRed, invalidCount, colorReset, colorReset)
	}
}