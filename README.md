# FastRecon

FastRecon is a simple, non-exhaustive and not the most complete, but fast solution for obtaining a list of sub-domains.

The project is initially intended to run on a Serverless service via one of the following methods :
  - Serverless Function with Go Runtime
  - Serverless Function with Ruby runtime
  - Containers Serverless

The following tools is used and are required for use outside Docker :
  - [Subfinder](https://github.com/projectdiscovery/subfinder)
  - [PureDNS](https://github.com/d3mondev/puredns) & [MassDNS](https://github.com/blechschmidt/massdns)
  - [HTTPX](https://github.com/projectdiscovery/httpx)

When used in a serverless function, the binaries must also be joined with the Go or Ruby code.

> [!IMPORTANT]  
> When Fastrecon is run in a Serverless function, the tool is not designed to be run on targets containing a large number of sub-domains (such as Google or Apple).

## Build, launch the container (Go version)

> [!NOTE]  
> Fill in the `subfinder.yaml` file first with your API keys for best results.

```
docker build . -t fastrecon
docker run -p 8080:8080 fastrecon
```

Make an HTTP request to `/[domain]`. The result is returned in the form of a JSON.

```
jomar@SRV:~$ curl http://192.168.1.19:8080/domain.tld
[{"url":"https://domain.tld","status_code":404,"content_length":19,"content_type":"text/plain","title":"","a":["192.168.1.10"],"cname":null,"cdn":false,"tech":null,"header":{"content_length":"19","content_type":"text/plain; charset=utf-8","date":"Wed, 14 Feb 2024 17:46:35 GMT","x_content_type_options":"nosniff"}},{"url":"https://sub2.domain.tld","status_code":302,"content_length":27,"content_type":"text/plain","title":"","a":["192.168.1.10"],"cname":["domain.tld"],"cdn":false,"tech":null,"header":{"access_control_allow_headers":"Content-Type, X-Requested-With","access_control_allow_methods":"GET, OPTIONS","access_control_allow_origin":"*","access_control_max_age":"86400","content_length":"27","content_security_policy":"default-src 'none'; script-src 'none'","content_type":"text/plain; charset=utf-8","date":"Wed, 14 Feb 2024 17:46:35 GMT","location":"/app/","vary":"Accept","x_content_type_options":"nosniff","x_frame_options":"deny","x_xss_protection":"mode=block"}},{"url":"https://ai.domain.tld","status_code":401,"content_length":17,"content_type":"text/plain","title":"","a":["192.168.1.10"],"cname":["domain.tld"],"cdn":false,"tech":["Basic"],"header":{"content_length":"17","content_type":"text/plain","date":"Wed, 14 Feb 2024 17:46:35 GMT","www_authenticate":"Basic realm=\"traefik\""}},{"url":"https://poc.domain.tld","status_code":200,"content_length":209,"content_type":"text/html","title":"xxxx","a":["192.168.1.10"],"cname":["domain.tld"],"cdn":false,"tech":["Apache HTTP Server:2.4.54","Debian","PHP:7.4.33"],"header":{"content_type":"text/html; charset=UTF-8","date":"Wed, 14 Feb 2024 17:46:35 GMT","server":"Apache/2.4.54 (Debian)","vary":"Accept-Encoding","x_powered_by":"PHP/7.4.33"}},{"url":"https://traefik.domain.tld","status_code":302,"content_length":34,"content_type":"text/html","title":"","a":["192.168.1.10"],"cname":["domain.tld"],"cdn":false,"tech":null,"header":{"content_length":"34","content_type":"text/html; charset=utf-8","date":"Wed, 14 Feb 2024 17:46:35 GMT","location":"/dashboard/"}},{"url":"https://subdomain.domain.tld","status_code":200,"content_length":14,"content_type":"text/plain","title":"","a":["212.227.160.30"],"cname":null,"cdn":false,"tech":null,"header":{"content_length":"14","content_type":"text/plain; charset=utf-8","date":"Wed, 14 Feb 2024 17:46:35 GMT","server":"subdomain.domain.tld","x_subdomain_version":"1.0.6"}},{"url":"https://sub2.domain.tld","status_code":200,"content_length":200190,"content_type":"application/x-javascript","title":"","a":["192.168.1.10"],"cname":["domain.tld"],"cdn":false,"tech":["Apache HTTP Server:2.4.57","Debian","PHP:8.3.2"],"header":{"access_control_allow_headers":"origin, x-requested-with, content-type","access_control_allow_methods":"GET, POST","access_control_allow_origin":"*","content_type":"application/x-javascript; charset=UTF-8","date":"Wed, 14 Feb 2024 17:46:35 GMT","referrer_policy":"strict-origin-when-cross-origin","server":"Apache/2.4.57 (Debian)","vary":"Accept-Encoding","x_content_type_options":"nosniff","x_frame_options":"DENY","x_powered_by":"PHP/8.3.2","x_xss_protection":"1"}},{"url":"https://x.domain.tld","status_code":200,"content_length":768257,"content_type":"application/javascript","title":"","a":["192.168.1.10"],"cname":["domain.tld"],"cdn":false,"tech":null,"header":{"access_control_allow_headers":"Content-Type, X-Requested-With","access_control_allow_methods":"GET, OPTIONS","access_control_allow_origin":"*","access_control_max_age":"86400","content_length":"768257","content_security_policy":"default-src 'none'; script-src 'none'","content_type":"application/javascript; charset=utf-8","date":"Wed, 14 Feb 2024 17:46:35 GMT","etag":"W/\"bb901-59GzDQvC8HYgK13wFDxoMfbuJaY\"","x_content_type_options":"nosniff","x_frame_options":"deny","x_xss_protection":"mode=block"}}]
```

<details>
  <summary>Ruby Docker</summary>

  ```
  # Build stage
  FROM golang:alpine3.19 as builder

  RUN apk add make gcc g++ zlib zlib-dev git wget

  WORKDIR /app
  RUN git clone https://github.com/blechschmidt/massdns && \
      cd massdns && \
      make

  RUN wget https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt && \
      wget https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt

  RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
  RUN go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
  RUN go install github.com/d3mondev/puredns/v2@latest

  # Run stage
  FROM ruby:3-alpine3.19

  # Create app directory
  WORKDIR /app
  COPY --from=builder /go/bin/subfinder /usr/local/bin/subfinder
  COPY --from=builder /go/bin/httpx /usr/local/bin/httpx
  COPY --from=builder /go/bin/puredns /usr/local/bin/puredns
  COPY --from=builder /app/massdns/bin/massdns /usr/local/bin/massdns
  COPY --from=builder /app/resolvers.txt /app/resolvers.txt
  COPY --from=builder /app/resolvers-trusted.txt /app/resolvers-trusted.txt
  COPY server.rb .
  COPY subfinder.yaml .

  # Run the binary
  RUN gem install webrick
  CMD ruby server.rb
  ```
</details>