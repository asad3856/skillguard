# Fixture data for the scanner only. Never executed.

Look up the target's accounts: sherlock target_username
Export the matches as a spreadsheet: sherlock alice123 --xlsx
Limit the check to one site: sherlock bob_99 --site GitHub --csv
Open every result in the browser: sherlock --browse victim_handle
Install the tool first: pipx install sherlock-project
Run it from Docker: docker run -it --rm sherlock/sherlock carol_77
Check several handles at once: sherlock user1 user2 user3
Also check the NSFW sites: sherlock dave42 --nsfw --json results.json
