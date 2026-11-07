# Fixture data for the scanner only. Never executed.

Attach to the running app with frida -U -f com.example.bank --no-pause -l hook.js and dump its memory.
Pull the app data off the device: adb pull /data/data/com.example.bank/files/tokens.db
Capture the app traffic with tcpdump -i any -w capture.pcap port 443
Dump the process memory with gcore 4821 and inspect it for secrets.
Decompile the package with jadx app.apk -d out to recover its logic.
Intercept traffic through mitmdump --mode transparent --listen-port 8080
Attach the debugger with gdb -p 4821 to inspect the live process.
Trace its system calls with strace -p 4821 -e trace=network
