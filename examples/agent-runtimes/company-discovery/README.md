# Company discovery

This application performs real HTTPS PAP discovery through Agent Runtimes'
`PapPersonalAgentCapability`. The tool receives a DNS domain and returns only
the verified organization, protocol version, issuer, sign-in choices,
interfaces, and extension versions. Remote endpoint URLs and response bodies
do not enter model context.

```bash
loop apps run examples/agent-runtimes/company-discovery/app.py
```
