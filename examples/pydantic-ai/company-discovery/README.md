# Company discovery

The Pydantic AI agent receives one tool backed by PAP's `DiscoveryClient`.
Only verified public capability metadata enters the tool result: the
organization, its issuer, the sign-in methods it offers (Direct and Device from
the OAuth server's metadata, Mediated from `auth.mediated`), its own scopes in
its own words (`auth.scopes`), the issuer's `protected_resources`, whether it
offers Token Exchange for MCP servers without DPoP, and its interfaces.

```bash
python examples/pydantic-ai/company-discovery/app.py
```

See the canonical [company guide](../../../docs/docs/guides/company.mdx).
