# ⚡FastRecon

FastRecon is a fast and simple tool for discovering subdomains of a target domain. It is designed to be non-exhaustive and is not intended to be the most complete solution, but it is ideal for quickly identifying subdomains.

  * Fast and efficient subdomain discovery
  * Compatible with Go Serverless functions
  * Uses popular open source tools such as [Subfinder](https://github.com/projectdiscovery/subfinder), [PureDNS](https://github.com/d3mondev/puredns), [MassDNS](https://github.com/blechschmidt/massdns) & [HTTPX](https://github.com/projectdiscovery/httpx)
  * Returns results in JSON format for easy integration with other tools
  * Supports raw output mode for simple domain lists

When used in a serverless function, the binaries must also be joined with the Go code.

> [!IMPORTANT]
> When Fastrecon is run in a Serverless function, the tool is not designed to be run on targets containing a large number of sub-domains (such as Google or Apple).

The Docker image produced is very light despite the many embedded binaries, making it perfect for Serverless use.

![Docker image](https://zupimages.net/up/24/07/evjx.png)

## Build, launch the container (Go version)

> [!NOTE]
> Fill in the `subfinder.yaml` file first with your API keys for best results.

```
docker build . -t fastrecon
docker run -p 8080:8080 fastrecon
```

## Usage

Make HTTP requests to `/?domain=[target_domain]` with optional parameters.

### Parameters

- `domain` (required): The target domain to scan
- `raw` (optional): Set to `true` to return only the list of discovered subdomains without additional metadata

### Examples

**Full scan with detailed JSON output:**
```bash
curl "http://localhost:8080/?domain=example.com"
```

**Raw output (domains only):**
```bash
curl "http://localhost:8080/?domain=example.com&raw=true"
```

### Output Formats

#### Full JSON Output (default)
Returns a JSON array with detailed information about each subdomain:

```json
[
  {
    "url": "https://example.com",
    "status_code": 200,
    "content_length": 1234,
    "content_type": "text/html",
    "title": "Example Domain",
    "a": ["93.184.216.34"],
    "cname": null,
    "cdn": false,
    "tech": ["Apache HTTP Server:2.4.41"],
    "header": {
      "content_type": "text/html; charset=UTF-8",
      "server": "Apache/2.4.41 (Ubuntu)"
    }
  }
]
```

#### Raw Output (raw=true)
Returns a simple list of discovered subdomains:

```
https://example.com
https://www.example.com
https://api.example.com
https://mail.example.com
```

## Performance

Example of resources consumption in a Serverless Container with 560mVCPU & 512MB RAM:
  * 220 seconds with a cold start for a recon on a domain with about 500 subdomains

![Resources Consumption](https://zupimages.net/up/24/07/7lsp.png)
