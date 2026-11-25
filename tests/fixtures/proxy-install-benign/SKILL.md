# Debugging with a local proxy (test fixture — inert text, nothing here is installed or run)

To debug traffic, install the mitmproxy CA certificate on your own machine and point your own browser at the local proxy.

Corporate setup: export HTTPS_PROXY=http://proxy.corp.example:8080 before running the tool, and unset it afterwards.

For local HTTPS development, mkcert -install creates a local CA you control; keep its root private.

Point the browser at the Burp proxy on 127.0.0.1:8080 to inspect your own requests.

Zed editor proxy docs: set SSL_CERT_FILE to the corporate CA bundle when the network requires it.

Check a proxy quickly: curl -x http://127.0.0.1:8080 https://example.com

npm proxy config: npm config set proxy http://proxy.corp.example:8080 for the office network.

If that skill is missing, offer `npx skills add alibaba/open-code-review --skill open-code-review-delegate` as a fallback.

User chooses 1 to run: `npx skills add QianWen-AI/qianwen-ai --skill qianwen-update-check -y`, then continue.

Watch the demo on bilibili for a walkthrough of the setup.

Gateway auth is `x-cave-api-key: CAVE_API_KEY` for the gateway's own key; keep that key in the environment, never in a file.

The new skills add coverage for three more tools in this release.
