package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/timothy90990/golfitester/scanner"
)

func main() {
	// Create a custom flag set for better help output
	flagSet := flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	flagSet.Usage = func() {
		fmt.Fprintf(os.Stderr, "GoLFITester - A Local File Inclusion vulnerability scanner\n\n")
		fmt.Fprintf(os.Stderr, "Usage: %s [options]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Options:\n")
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
		fmt.Fprintf(os.Stderr, "  -h, --help                Display this help message\n")
		
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  %s -u \"http://example.com/page.php?file=test\"\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -u \"http://example.com/page.php\" -p \"file,include\"\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -r \"burp_request.txt\" -p \"file\"\n", os.Args[0])
	}

	// Define command line flags with short and long versions
	// We'll manually parse them with a custom parser
	if len(os.Args) == 1 || (len(os.Args) > 1 && (os.Args[1] == "-h" || os.Args[1] == "--help")) {
		flagSet.Usage()
		os.Exit(0)
	}

	// Initialize variables for flags
	var targetURL, params, wordlist, outputFile, cookies, headers, requestFile string
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
		default:
			if strings.HasPrefix(args[i], "-") {
				fmt.Printf("Unknown option: %s\n", args[i])
				flagSet.Usage()
				os.Exit(1)
			}
		}
	}

	// Check if required flags are provided
	if targetURL == "" && requestFile == "" {
		fmt.Println("Error: Either Target URL or Request file is required")
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

	// Initialize scanner configuration
	config := scanner.Config{
		TargetURL:     targetURL,
		ParamsList:    paramsList,
		ScanAllParams: scanAllParams,
		Wordlist:      wordlist,
		Threads:       threads,
		Timeout:       timeout,
		Verbose:       verbose,
		OutputFile:    outputFile,
		Cookies:       cookies,
		Headers:       headers,
		Depth:         depth,
		RequestFile:   requestFile,
	}

	// Create and run scanner
	scanner := scanner.NewScanner(config)
	fmt.Println("Starting LFI vulnerability scan...")
	
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
	if outputFile != "" {
		err := scanner.SaveResults(results, outputFile)
		if (err != nil) {
			fmt.Printf("Error saving results to file: %s\n", err)
		} else {
			fmt.Printf("Results saved to %s\n", outputFile)
		}
	}
}