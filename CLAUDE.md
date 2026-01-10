# Project Guidelines

## Sudo Commands

All commands requiring `sudo` must use the askpass helper approach:

```bash
SUDO_ASKPASS=~/.sudo_pass.sh sudo -A <command>
```

Never use interactive sudo or pipe passwords directly. The `-A` flag tells sudo to use the `SUDO_ASKPASS` helper program to obtain the password.
