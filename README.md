# ⚡FastRecon

FastRecon is a fast and simple tool for discovering subdomains of a target domain. It is designed to be non-exhaustive and is not intended to be the most complete solution, but it is ideal for quickly identifying subdomains.

  * Fast and efficient subdomain discovery
  * Compatible with Go Serverless functions
  * Uses popular open source tools such as [Subfinder](https://github.com/projectdiscovery/subfinder), [PureDNS](https://github.com/d3mondev/puredns), [MassDNS](https://github.com/blechschmidt/massdns) & [HTTPX](https://github.com/projectdiscovery/httpx)
  * Returns results in JSON format for easy integration with other tools

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

To use FastRecon, make an HTTP request to `/[domain]`. The result is returned in the form of a JSON array containing information about each subdomain, including its URL, status code, content length, content type, title, IP address, CNAME, CDN status, technology used, and HTTP headers.

```
jomar@SRV:~$ curl http://192.168.1.19:8080/domain.tld
[{"url":"https://domain.tld","status_code":404,"content_length":19,"content_type":"text/plain","title":"","a":["192.168.1.10"],"cname":null,"cdn":false,"tech":null,"header":{"content_length":"19","content_type":"text/plain; charset=utf-8","date":"Wed, 14 Feb 2024 17:46:35 GMT","x_content_type_options":"nosniff"}},{"url":"https://sub2.domain.tld","status_code":302,"content_length":27,"content_type":"text/plain","title":"","a":["192.168.1.10"],"cname":["domain.tld"],"cdn":false,"tech":null,"header":{"access_control_allow_headers":"Content-Type, X-Requested-With","access_control_allow_methods":"GET, OPTIONS","access_control_allow_origin":"*","access_control_max_age":"86400","content_length":"27","content_security_policy":"default-src 'none'; script-src 'none'","content_type":"text/plain; charset=utf-8","date":"Wed, 14 Feb 2024 17:46:35 GMT","location":"/app/","vary":"Accept","x_content_type_options":"nosniff","x_frame_options":"deny","x_xss_protection":"mode=block"}},{"url":"https://ai.domain.tld","status_code":401,"content_length":17,"content_type":"text/plain","title":"","a":["192.168.1.10"],"cname":["domain.tld"],"cdn":false,"tech":["Basic"],"header":{"content_length":"17","content_type":"text/plain","date":"Wed, 14 Feb 2024 17:46:35 GMT","www_authenticate":"Basic realm=\"traefik\""}},{"url":"https://poc.domain.tld","status_code":200,"content_length":209,"content_type":"text/html","title":"xxxx","a":["192.168.1.10"],"cname":["domain.tld"],"cdn":false,"tech":["Apache HTTP Server:2.4.54","Debian","PHP:7.4.33"],"header":{"content_type":"text/html; charset=UTF-8","date":"Wed, 14 Feb 2024 17:46:35 GMT","server":"Apache/2.4.54 (Debian)","vary":"Accept-Encoding","x_powered_by":"PHP/7.4.33"}},{"url":"https://traefik.domain.tld","status_code":302,"content_length":34,"content_type":"text/html","title":"","a":["192.168.1.10"],"cname":["domain.tld"],"cdn":false,"tech":null,"header":{"content_length":"34","content_type":"text/html; charset=utf-8","date":"Wed, 14 Feb 2024 17:46:35 GMT","location":"/dashboard/"}},{"url":"https://subdomain.domain.tld","status_code":200,"content_length":14,"content_type":"text/plain","title":"","a":["212.227.160.30"],"cname":null,"cdn":false,"tech":null,"header":{"content_length":"14","content_type":"text/plain; charset=utf-8","date":"Wed, 14 Feb 2024 17:46:35 GMT","server":"subdomain.domain.tld","x_subdomain_version":"1.0.6"}},{"url":"https://sub2.domain.tld","status_code":200,"content_length":200190,"content_type":"application/x-javascript","title":"","a":["192.168.1.10"],"cname":["domain.tld"],"cdn":false,"tech":["Apache HTTP Server:2.4.57","Debian","PHP:8.3.2"],"header":{"access_control_allow_headers":"origin, x-requested-with, content-type","access_control_allow_methods":"GET, POST","access_control_allow_origin":"*","content_type":"application/x-javascript; charset=UTF-8","date":"Wed, 14 Feb 2024 17:46:35 GMT","referrer_policy":"strict-origin-when-cross-origin","server":"Apache/2.4.57 (Debian)","vary":"Accept-Encoding","x_content_type_options":"nosniff","x_frame_options":"DENY","x_powered_by":"PHP/8.3.2","x_xss_protection":"1"}},{"url":"https://x.domain.tld","status_code":200,"content_length":768257,"content_type":"application/javascript","title":"","a":["192.168.1.10"],"cname":["domain.tld"],"cdn":false,"tech":null,"header":{"access_control_allow_headers":"Content-Type, X-Requested-With","access_control_allow_methods":"GET, OPTIONS","access_control_allow_origin":"*","access_control_max_age":"86400","content_length":"768257","content_security_policy":"default-src 'none'; script-src 'none'","content_type":"application/javascript; charset=utf-8","date":"Wed, 14 Feb 2024 17:46:35 GMT","etag":"W/\"bb901-59GzDQvC8HYgK13wFDxoMfbuJaY\"","x_content_type_options":"nosniff","x_frame_options":"deny","x_xss_protection":"mode=block"}}]
```

Example of resources consumption in a Serverless Container with 560mVCPU & 512MB RAM :
  * 220 seconds with a cold start for a recon on a domain with about 500 subdomains

![Resources Consumption](https://zupimages.net/up/24/07/7lsp.png)