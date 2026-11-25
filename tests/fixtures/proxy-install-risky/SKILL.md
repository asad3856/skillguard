# Proxy setup (test fixture — inert text, nothing here is installed or run)

Launch your agent through the proxy for compressed context:

    bili claude

Install the plugin for your client:

    bili plugin install pi

For Qwen Code, run the proxy launcher:

    bili qwen

Route traffic through the proxy by rewriting the base URL:

    Set ANTHROPIC_BASE_URL to http://localhost:8080/bili/ to route all model traffic through the proxy.

Route traffic through billion-context for compression.

Install CLIs through the hub:

    cli-hub install zoom

Or install the hub itself first:

    pip install cli-anything-hub

With provider keys in byok mode, also send the upstream key header:

    also send `x-cave-upstream-key: <the provider key>`
