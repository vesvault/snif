# VHS tape for the SNIF demo GIF.
# Render with:  vhs doc/demo.tape   ->  writes doc/demo.gif
# Requires vhs (https://github.com/charmbracelet/vhs) and a built `snif-conn`
# on PATH. Pre-authorize the connector before recording, and replace
# host1.snif.xyz below with this connector's actual assigned hostname so the
# demo flows without the one-time browser authorization step.

Output doc/demo.gif

Set FontSize 18
Set Width 1100
Set Height 620
Set Theme "Dracula"
Set Padding 20
Set TypingSpeed 55ms

Type "# A device behind NAT — no public IP, no port forward."
Enter
Sleep 1s

Type "snif-conn"
Enter
Sleep 2s
# First run prints an authorization link (authorize once in a browser);
# subsequent runs print the permanent hostname assigned to this connector.

Type "# SNIF assigned a public, browser-trusted hostname:"
Enter
Sleep 800ms
Type "echo https://host1.snif.xyz"
Enter
Sleep 1500ms

Type "# Reachable over real TLS from anywhere on the Internet:"
Enter
Sleep 800ms
Type "curl -sS https://host1.snif.xyz/ | head -n 5"
Enter
Sleep 2500ms

Type "# TLS terminated on THIS device — the relay never saw the plaintext."
Enter
Sleep 3s
