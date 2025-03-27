package scanner

import (
	"fmt"
	"net/url"
	"strings"
)

// ParameterDiscovery attempts to discover parameters that might be vulnerable to LFI
func (s *Scanner) ParameterDiscovery(targetURL string) []string {
	if s.config.Verbose {
		fmt.Println("Starting parameter discovery...")
	}
	
	var discoveredParams []string
	
	// Common parameter names that are often vulnerable to LFI
	commonParams := []string{
		"file", "document", "page", "path", "data", "load", "read",
		"include", "dir", "view", "content", "template", "module",
		"display", "show", "site", "default", "language", "conf",
		"conf_file", "config", "folder", "prefix", "debug", "cat",
		"id", "img", "filename", "action", "body", "url", "path", 
		"name", "src", "dest", "loc", "location", "redirect",
	}
	
	// Extract parameters from the URL if any
	u, err := url.Parse(targetURL)
	if err == nil {
		// Check for parameters in the query string
		for param := range u.Query() {
			discoveredParams = append(discoveredParams, param)
		}
		
		// Check for parameters directly in the path (e.g., /param=value)
		// This handles cases like http://localhost:8000/test=awg
		pathParams := extractPathParams(u.Path)
		for _, param := range pathParams {
			// Only add if not already discovered
			if !containsParam(discoveredParams, param) {
				discoveredParams = append(discoveredParams, param)
			}
		}
	}
	
	// If no parameters were found in the URL, prompt the user
	if len(discoveredParams) == 0 {
		fmt.Println("No parameters found in the URL. Would you like to test with common parameter names? (y/n)")
		var response string
		fmt.Scanln(&response)
		if !strings.HasPrefix(strings.ToLower(response), "y") {
			fmt.Println("Please specify parameters using --param or --params flags")
			return []string{}
		}
	} else {
		// Parameters were found, but let's confirm with the user
		fmt.Printf("Found the following parameters in the URL: %s\n", strings.Join(discoveredParams, ", "))
		fmt.Println("Would you like to test only these parameters? (y/n)")
		var response string
		fmt.Scanln(&response)
		if !strings.HasPrefix(strings.ToLower(response), "y") {
			fmt.Println("Would you like to add common parameter names to test as well? (y/n)")
			fmt.Scanln(&response)
			if !strings.HasPrefix(strings.ToLower(response), "y") {
				fmt.Println("Please specify additional parameters using --param or --params flags")
				return discoveredParams
			}
		} else {
			// User wants to test only the discovered parameters
			return discoveredParams
		}
	}
	
	// Add common parameters if requested or if no parameters were found
	for _, param := range commonParams {
		// Only add if not already discovered
		if !containsParam(discoveredParams, param) {
			discoveredParams = append(discoveredParams, param)
		}
	}
	
	if s.config.Verbose {
		fmt.Printf("Discovered %d parameters to test\n", len(discoveredParams))
	}
	
	return discoveredParams
}

// extractPathParams extracts parameters from URL path segments like /param=value
func extractPathParams(path string) []string {
	var params []string
	// Split the path into segments
	segments := strings.Split(path, "/")
	
	// Check each segment for param=value pattern
	for _, segment := range segments {
		if strings.Contains(segment, "=") {
			parts := strings.SplitN(segment, "=", 2)
			if len(parts) == 2 && parts[0] != "" {
				params = append(params, parts[0])
			}
		}
	}
	
	return params
}

// containsParam checks if a parameter is already in the slice
func containsParam(params []string, param string) bool {
	for _, p := range params {
		if p == param {
			return true
		}
	}
	return false
}

// GenerateFilterEvasionPayloads generates payloads that try to evade WAF or filters
func GenerateFilterEvasionPayloads(basePayload string) []string {
	evasionTechniques := []struct {
		name     string
		transform func(string) string
	}{
		{
			name: "double_encoding",
			transform: func(p string) string {
				// Double URL encoding
				p = strings.ReplaceAll(p, ".", "%252e")
				p = strings.ReplaceAll(p, "/", "%252f")
				p = strings.ReplaceAll(p, "\\", "%255c")
				return p
			},
		},
		{
			name: "null_byte",
			transform: func(p string) string {
				// Add null byte to end
				return p + "%00"
			},
		},
	}

	var payloads []string
	payloads = append(payloads, basePayload)
	
	for _, technique := range evasionTechniques {
		payloads = append(payloads, technique.transform(basePayload))
	}
	
	return payloads
}