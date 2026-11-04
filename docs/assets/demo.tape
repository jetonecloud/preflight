# Renders docs/assets/demo.gif from a real `preflight demo` run.
# Install vhs (https://github.com/charmbracelet/vhs), then:
#   vhs docs/assets/demo.tape

Output docs/assets/demo.gif

Set Shell "bash"
Set FontSize 16
Set Width 1200
Set Height 720
Set Padding 20
Set TypingSpeed 60ms
Set Theme "Dracula"

Hide
Type "cd /mnt/c/Users/user/documents/github/jetonecloud/preflight"
Enter
Type "clear"
Enter
Show

Type "uv run preflight demo --terminal"
Sleep 600ms
Enter

# "Save the JSON export as well?" - accept the default (yes).
Sleep 1500ms
Enter

# Checks print one at a time (DEMO_PACE), then the intro screen.
Sleep 4500ms

# Intro screen: any non-'q' key starts the pager.
Enter
Sleep 900ms

# Step through the first couple of sections by hand...
Enter
Sleep 1400ms
Enter
Sleep 1400ms

# ...then dump the rest of the report at once.
Type "a"
Sleep 2200ms

# Quit the pager cleanly.
Type "q"
Sleep 800ms
