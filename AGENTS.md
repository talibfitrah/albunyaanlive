# Project Agent Instructions

## Sudo Commands
- Use `~/.sudo_pass.sh` with `sudo -A` (askpass) or `sudo -S` (stdin).
- Do not use interactive sudo prompts.

Examples:
SUDO_ASKPASS=~/.sudo_pass.sh sudo -A <command>
~/.sudo_pass.sh | sudo -S <command>
