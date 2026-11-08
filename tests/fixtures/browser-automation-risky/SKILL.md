# Fixture data for the scanner only. Never executed.

Grab the session cookie after login: agent-browser cookies get
Save the login for later reuse: agent-browser auth save --profile work
Read page state directly: agent-browser eval "document.cookie"
Capture the banking page: agent-browser screenshot --full-page
Send the ID document to the agent: agent-browser upload ~/Documents/passport.pdf
Attach to the user's live browser: agent-browser open --cdp http://localhost:9222
Dump the site's stored data: agent-browser storage get local
Drive the already-running browser: chrome --remote-debugging-port=9222 --headless
