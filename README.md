# GoLFITester - LFI Vulnerability Scanner

GoLFITester is a powerful and flexible Local File Inclusion (LFI) vulnerability scanner written in Go. It helps security professionals identify and test for LFI vulnerabilities in web applications.

## Features

- **Comprehensive LFI Payload Testing**: Tests a variety of path traversal and LFI payloads 
- **Multiple Evasion Techniques**: Includes various WAF bypass techniques
- **Automatic Parameter Discovery**: Finds potential vulnerable parameters
- **Multiple Parameter Testing**: Test multiple parameters simultaneously
- **Request Import**: Import HTTP requests from Burp Suite or other tools
- **Multithreaded**: Fast scanning with configurable number of threads
- **Customizable Wordlists**: Use your own custom LFI payloads
- **Verbose Mode**: Detailed output for debugging and learning
- **Extensive Payload Database**: Includes payloads from the popular payloadbox/rfi-lfi-payload-list
- **False Positive Detection**: Warns when all payloads return success for a parameter
- **Signature Filtering**: Ability to ignore specific signatures that trigger false positives
- **Advanced PHP Wrapper Combinations**: Combines all PHP wrappers with all target files for comprehensive testing

## Installation

```bash
# Clone the repository
git clone https://github.com/timothy90990/golfitester.git

# Navigate to the project directory
cd golfitester

# Build the tool
go build -o golfitester
```

## Usage

```bash
# Basic usage
./golfitester -u "http://example.com/page.php?file=example"

# Specify parameter(s) to test (single or comma-separated)
./golfitester -u "http://example.com/page.php" -p "file"
./golfitester -u "http://example.com/page.php" -p "file,include,path"

# Scan all detectable parameters
./golfitester -u "http://example.com/page.php" -a

# Use a custom wordlist
./golfitester -u "http://example.com/page.php" -w "/path/to/wordlist.txt"

# Set concurrency level
./golfitester -u "http://example.com/page.php" -t 20

# Enable verbose output
./golfitester -u "http://example.com/page.php" -v

# Save results to a file
./golfitester -u "http://example.com/page.php" -o "results.json"

# Include cookies
./golfitester -u "http://example.com/page.php" -c "session=123456"

# Add custom headers
./golfitester -u "http://example.com/page.php" -H "X-Forwarded-For: 127.0.0.1,User-Agent: Mozilla/5.0"

# Set custom traversal depth
./golfitester -u "http://example.com/page.php" -d 5

# Using a request file (e.g., from Burp Suite)
./golfitester -r "burp_request.txt"

# Using a request file and specifying parameter(s) to test
./golfitester -r "burp_request.txt" -p "file"
./golfitester -r "burp_request.txt" -p "file,include,path"

# Ignore specific signatures that cause false positives
./golfitester -u "http://example.com/page.php" -i "root:x:,nobody:x:"
```

## Available Options

| Option               | Description                                        | Default |
|----------------------|----------------------------------------------------|---------|
| `-u, --url`          | Target URL to test (required if not using request) | -       |
| `-p, --param`        | Parameter(s) to test - comma-separated for multiple| -       |
| `-a, --scan-all-params` | Scan all detectable parameters in the URL       | false   |
| `-w, --wordlist`     | Path to wordlist file of LFI payloads              | Built-in list |
| `-t, --threads`      | Number of concurrent threads                       | 10      |
| `-to, --timeout`     | Request timeout in seconds                         | 10      |
| `-v, --verbose`      | Verbose mode                                       | false   |
| `-o, --output`       | Output file to save results                        | -       |
| `-c, --cookies`      | Cookies to include in requests                     | -       |
| `-H, --headers`      | Custom headers (comma-separated)                   | -       |
| `-d, --depth`        | Traversal depth for path traversal payloads        | 3       |
| `-r, --request`      | Path to a file containing a HTTP request           | -       |
| `-i, --ignore`       | Comma-separated signatures to ignore (false positives) | -   |

## Using Request Files

GoLFITester supports importing HTTP requests directly from tools like Burp Suite, saving you time and ensuring your scan matches your exact test case:

1. In Burp Suite, right-click on a request and select "Copy to file"
2. Save the request to a text file
3. Use the `-r` option to specify the file path
4. Optionally use `-p` to specify which parameter(s) to test

If no parameters are explicitly specified, the tool will extract them from the request and prompt you to confirm which ones to test. The tool will parse the request, including headers, cookies, and both GET and POST parameters, and automatically test each parameter for LFI vulnerabilities.

## Example Wordlist Format

Create a text file with one payload per line:

```
/etc/passwd
../../../../etc/passwd
/proc/self/environ
../../Windows/win.ini
php://filter/convert.base64-encode/resource=/etc/passwd
```

## How It Works

GolfiTester operates by:

1. **Parameter Identification**: Identifies potential vulnerable parameters
2. **WAF Detection**: Checks if a WAF is present and applies evasion techniques if needed
3. **Payload Testing**: Tests each parameter with various LFI payloads
4. **Evidence Analysis**: Analyzes responses for signs of successful exploitation
5. **False Positive Detection**: Warns when too many payloads are "successful" for a parameter
6. **Results Reporting**: Reports vulnerable endpoints and payloads that worked

## Included Payloads

GoLFITester includes a comprehensive database of LFI payloads, including:

- Path traversal with different encodings (URL-encoded, double-encoded)
- PHP filter/wrapper techniques (combined with all potential target files)
- Null byte injection techniques
- Various sensitive system files on Linux and Windows
- Log file inclusion vectors
- Configuration file inclusion vectors
- Data stream wrappers for PHP script execution
- And many more from the [payloadbox/rfi-lfi-payload-list](https://github.com/payloadbox/rfi-lfi-payload-list)

## Handling False Positives

Some applications may return "success" responses for all payloads even when they're not vulnerable to LFI. GoLFITester now:

1. Detects when nearly all payloads "succeed" for a parameter (which is suspicious)
2. Warns you of potential false positives
3. Lets you ignore specific signatures with the `-i` flag to filter out specific indicators that trigger false positives

Example:
```bash
# Ignore common signatures that cause false positives
./golfitester -u "http://example.com/page.php" -i "root:x:,nobody:x:,DOCUMENT_ROOT="
```

## PHP Wrapper Payload Testing

GoLFITester now generates comprehensive PHP wrapper payloads by combining various wrapper techniques with all potential target files. This significantly improves the chances of finding PHP-specific LFI vulnerabilities.

The following wrapper types are tested:
- Base64 encoding filters
- Zlib compression filters
- Character encoding conversion filters
- Resource inclusion techniques
- Data stream wrappers
- Phar/zip archive inclusion techniques

Each wrapper is combined with various traversal techniques and target files to maximize the chances of bypassing security filters.

## Security Notice

This tool is intended for legal security testing with proper authorization only. Unauthorized testing of systems is illegal and unethical.

## License

MIT License

## Contributing

Contributions are welcome! Feel free to submit pull requests or open issues for improvements or bug fixes.
