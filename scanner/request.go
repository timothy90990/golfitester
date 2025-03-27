package scanner

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
)

// RequestInfo stores parsed information from a request file
type RequestInfo struct {
	Method      string
	URL         string
	Headers     map[string]string
	Body        string
	Cookies     string
	QueryParams map[string]string
	FormParams  map[string]string
}

// ParseRequestFile parses a HTTP request file (e.g., from Burp Suite)
func ParseRequestFile(filePath string) (*RequestInfo, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("error opening request file: %v", err)
	}
	defer file.Close()

	// Read the file content
	content, err := io.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("error reading request file: %v", err)
	}

	// Parse the request
	reader := bufio.NewReader(bytes.NewReader(content))
	
	// Parse the request line
	requestLine, err := reader.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("error reading request line: %v", err)
	}
	
	// Extract method and path
	parts := strings.Split(strings.TrimSpace(requestLine), " ")
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid request line format: %s", requestLine)
	}
	
	method := parts[0]
	path := parts[1]
	
	// Parse headers
	headers := make(map[string]string)
	var host string
	var cookies string

	for {
		line, err := reader.ReadString('\n')
		if err != nil && err != io.EOF {
			return nil, fmt.Errorf("error reading header: %v", err)
		}
		
		line = strings.TrimSpace(line)
		if line == "" {
			break // End of headers
		}
		
		colonIndex := strings.Index(line, ":")
		if colonIndex > 0 {
			headerName := strings.TrimSpace(line[:colonIndex])
			headerValue := strings.TrimSpace(line[colonIndex+1:])
			
			if strings.ToLower(headerName) == "host" {
				host = headerValue
			} else if strings.ToLower(headerName) == "cookie" {
				cookies = headerValue
			}
			
			headers[headerName] = headerValue
		}
	}
	
	// Read the body if present
	var body string
	bodyBytes, _ := io.ReadAll(reader)
	if len(bodyBytes) > 0 {
		body = string(bodyBytes)
	}
	
	// Construct the full URL
	var fullURL string
	if host != "" {
		// Check if the path starts with http
		if strings.HasPrefix(path, "http") {
			fullURL = path
		} else {
			// Check if the host includes the scheme
			if strings.HasPrefix(host, "http") {
				fullURL = host + path
			} else {
				// Assume HTTP if no scheme
				fullURL = "http://" + host + path
			}
		}
	} else {
		// No host header found, assume the path is a complete URL
		fullURL = path
	}
	
	// Parse query parameters from URL
	queryParams := make(map[string]string)
	if parsedURL, err := url.Parse(fullURL); err == nil {
		for k, v := range parsedURL.Query() {
			if len(v) > 0 {
				queryParams[k] = v[0]
			}
		}
	}
	
	// Parse form parameters from body if it's form-encoded
	formParams := make(map[string]string)
	contentType, hasContentType := headers["Content-Type"]
	if hasContentType && strings.Contains(contentType, "application/x-www-form-urlencoded") && body != "" {
		formValues, err := url.ParseQuery(body)
		if err == nil {
			for k, v := range formValues {
				if len(v) > 0 {
					formParams[k] = v[0]
				}
			}
		}
	}
	
	return &RequestInfo{
		Method:      method,
		URL:         fullURL,
		Headers:     headers,
		Body:        body,
		Cookies:     cookies,
		QueryParams: queryParams,
		FormParams:  formParams,
	}, nil
}

// GetParametersFromRequest extracts all parameters from a request
func GetParametersFromRequest(req *RequestInfo) []string {
	var params []string
	
	// Extract query parameters
	for param := range req.QueryParams {
		params = append(params, param)
	}
	
	// Extract form parameters
	for param := range req.FormParams {
		if !containsParam(params, param) {
			params = append(params, param)
		}
	}
	
	// Check for parameters in URL path
	if parsedURL, err := url.Parse(req.URL); err == nil {
		pathParams := extractPathParams(parsedURL.Path)
		for _, param := range pathParams {
			if !containsParam(params, param) {
				params = append(params, param)
			}
		}
	}
	
	return params
}

// CreateHTTPRequestFromRequestInfo creates an http.Request from RequestInfo
func CreateHTTPRequestFromRequestInfo(reqInfo *RequestInfo, paramName, payload string) (*http.Request, error) {
	// Build URL with the payload inserted
	targetURL := reqInfo.URL
	
	// Parse the URL
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return nil, fmt.Errorf("error parsing URL: %v", err)
	}
	
	// Check if the parameter is in query parameters
	inQuery := false
	for param := range reqInfo.QueryParams {
		if param == paramName {
			inQuery = true
			break
		}
	}
	
	// Check if the parameter is in form parameters
	inForm := false
	for param := range reqInfo.FormParams {
		if param == paramName {
			inForm = true
			break
		}
	}
	
	// Check if the parameter is in path
	inPath := false
	pathSegments := strings.Split(parsedURL.Path, "/")
	for _, segment := range pathSegments {
		if strings.Contains(segment, "=") {
			parts := strings.SplitN(segment, "=", 2)
			if len(parts) == 2 && parts[0] == paramName {
				inPath = true
				break
			}
		}
	}
	
	var reqBody string
	var reqURL string
	
	if inQuery {
		// Modify query parameters
		q := parsedURL.Query()
		q.Set(paramName, payload)
		parsedURL.RawQuery = q.Encode()
		reqURL = parsedURL.String()
		reqBody = reqInfo.Body
	} else if inPath {
		// Modify path parameter
		for i, segment := range pathSegments {
			if strings.Contains(segment, "=") {
				parts := strings.SplitN(segment, "=", 2)
				if len(parts) == 2 && parts[0] == paramName {
					pathSegments[i] = parts[0] + "=" + payload
					break
				}
			}
		}
		parsedURL.Path = strings.Join(pathSegments, "/")
		reqURL = parsedURL.String()
		reqBody = reqInfo.Body
	} else if inForm {
		// Modify form parameters
		formValues, _ := url.ParseQuery(reqInfo.Body)
		formValues.Set(paramName, payload)
		reqBody = formValues.Encode()
		reqURL = reqInfo.URL
	} else {
		// Parameter not found, add it to query
		q := parsedURL.Query()
		q.Set(paramName, payload)
		parsedURL.RawQuery = q.Encode()
		reqURL = parsedURL.String()
		reqBody = reqInfo.Body
	}
	
	// Create request with the modified URL or body
	var req *http.Request
	if reqInfo.Method == "GET" || reqInfo.Method == "HEAD" || reqBody == "" {
		req, err = http.NewRequest(reqInfo.Method, reqURL, nil)
	} else {
		req, err = http.NewRequest(reqInfo.Method, reqURL, strings.NewReader(reqBody))
	}
	
	if err != nil {
		return nil, fmt.Errorf("error creating request: %v", err)
	}
	
	// Add headers
	for k, v := range reqInfo.Headers {
		// Skip Content-Length as it will be set automatically
		if strings.ToLower(k) != "content-length" {
			req.Header.Add(k, v)
		}
	}
	
	// If we modified the form body, ensure Content-Type is set
	if inForm {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	
	return req, nil
}