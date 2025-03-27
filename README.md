# GoLFITester - LFI Vulnerability Scanner

GoLFITester is a powerful and flexible Local File Inclusion (LFI) vulnerability scanner written in Go. It helps security professionals identify and test for LFI vulnerabilities in web applications.

## Features

- **Comprehensive LFI Payload Testing**: Tests a variety of path traversal and LFI payloads 
- **Multiple Evasion Techniques**: Includes various WAF bypass techniques
- **Automatic Parameter Discovery**: Finds potential vulnerable parameters
- **Multiple Parameter Testing**: Test multiple parameters simultaneously
- **Multithreaded**: Fast scanning with configurable number of threads
- **Customizable Wordlists**: Use your own custom LFI payloads
- **Verbose Mode**: Detailed output for debugging and learning
- **Extensive Payload Database**: Includes payloads from the popular payloadbox/rfi-lfi-payload-list

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
./golfitester --url "http://example.com/page.php?file=example"

# Specify a single parameter to test
./golfitester --url "http://example.com/page.php" --param "file"

# Specify multiple parameters to test
./golfitester --url "http://example.com/page.php" --params "file,include,path"

# Scan all detectable parameters
./golfitester --url "http://example.com/page.php" --scan-all-params

# Use a custom wordlist
./golfitester --url "http://example.com/page.php" --wordlist "/path/to/wordlist.txt"

# Set concurrency level
./golfitester --url "http://example.com/page.php" --threads 20

# Enable verbose output
./golfitester --url "http://example.com/page.php" --v

# Save results to a file
./golfitester --url "http://example.com/page.php" --o "results.json"

# Include cookies
./golfitester --url "http://example.com/page.php" --cookies "session=123456"

# Add custom headers
./golfitester --url "http://example.com/page.php" --headers "X-Forwarded-For: 127.0.0.1,User-Agent: Mozilla/5.0"

# Set custom traversal depth
./golfitester --url "http://example.com/page.php" --depth 5
```

## Available Options

| Option             | Description                                        | Default |
|--------------------|----------------------------------------------------|---------|
| `--url`            | Target URL to test (required)                      | -       |
| `--param`          | Single parameter name to test                      | -       |
| `--params`         | Comma-separated list of parameters to test         | -       |
| `--scan-all-params`| Scan all detectable parameters in the URL          | false   |
| `--wordlist`       | Path to wordlist file of LFI payloads              | Built-in list |
| `--threads`        | Number of concurrent threads                       | 10      |
| `--timeout`        | Request timeout in seconds                         | 10      |
| `--v`              | Verbose mode                                       | false   |
| `--o`              | Output file to save results                        | -       |
| `--cookies`        | Cookies to include in requests                     | -       |
| `--headers`        | Custom headers (comma-separated)                   | -       |
| `--depth`          | Traversal depth for path traversal payloads        | 3       |

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
5. **Results Reporting**: Reports vulnerable endpoints and payloads that worked

## Included Payloads

GolfiTester includes a comprehensive database of LFI payloads, including:

- Path traversal with different encodings (URL-encoded, double-encoded)
- PHP filter/wrapper techniques
- Null byte injection techniques
- Various sensitive system files on Linux and Windows
- Log file inclusion vectors
- Configuration file inclusion vectors
- And many more from the [payloadbox/rfi-lfi-payload-list](https://github.com/payloadbox/rfi-lfi-payload-list)

## Security Notice

This tool is intended for legal security testing with proper authorization only. Unauthorized testing of systems is illegal and unethical.

## License

MIT License

## Contributing

Contributions are welcome! Feel free to submit pull requests or open issues for improvements or bug fixes.
