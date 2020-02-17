NIOSSLHTTP1Client
---

This sample application provides a https client. Invoke it using one of the following syntaxes.

```bash
swift run NIOSSLHTTP1Client # Gets a content on a server on ::1, port 4433, using SSL/TLS
swift run NIOSSLHTTP1Client "https://example.com" # Gets a content on a server on example.com, port 443, using SSL/TLS 
swift run NIOSSLHTTP1Client "https://example.com:4433" # Gets a content on a server on example.com, port 4433, using SSL/TLS
```
