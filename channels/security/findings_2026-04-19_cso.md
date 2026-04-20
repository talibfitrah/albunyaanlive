# /cso findings — 2026-04-19T03:03:13+02:00

## Raw JSON
```json
{
    "findings": [
        {
            "severity": "critical",
            "title": "19 provider login accounts are publicly readable on GitHub",
            "location": "channels/ayyadonline_credentials.json",
            "why_it_matters": "The file that stores the usernames and passwords for our Egyptian provider was accidentally published to the internet along with the project's code. Anyone in the world who visits the project page on GitHub can open this file and see all 19 usernames and passwords in plain text. That means an outsider can log in with our accounts, overload them, get them banned, or impersonate us, and the provider will think it was really us.",
            "suggested_fix": "Right now: contact the provider and ask them to cancel all 19 accounts and issue new ones, then store the new ones only on the server and never in the project files. After that, scrub the file from the project's public history on GitHub so the old passwords stop being visible even to people looking at older versions."
        },
        {
            "severity": "major",
            "title": "The safety list that blocks secret files from being published does not cover this provider",
            "location": ".gitignore",
            "why_it_matters": "The project has a safety list that tells the system which sensitive files to keep private. That list protects two other providers but forgot to mention the Egyptian provider's file, which is why the passwords leaked in the first place. As it stands, the same mistake can happen again the next time a new provider is added.",
            "suggested_fix": "Add a general rule that automatically hides every file whose name ends with credentials, so any current or future provider is protected without anyone having to remember to update the list each time."
        }
    ]
}
```

## Plain reading

### 1. [critical] 19 provider login accounts are publicly readable on GitHub
- **Where:** channels/ayyadonline_credentials.json
- **Why it matters:** The file that stores the usernames and passwords for our Egyptian provider was accidentally published to the internet along with the project's code. Anyone in the world who visits the project page on GitHub can open this file and see all 19 usernames and passwords in plain text. That means an outsider can log in with our accounts, overload them, get them banned, or impersonate us, and the provider will think it was really us.
- **Suggested fix:** Right now: contact the provider and ask them to cancel all 19 accounts and issue new ones, then store the new ones only on the server and never in the project files. After that, scrub the file from the project's public history on GitHub so the old passwords stop being visible even to people looking at older versions.

### 2. [major] The safety list that blocks secret files from being published does not cover this provider
- **Where:** .gitignore
- **Why it matters:** The project has a safety list that tells the system which sensitive files to keep private. That list protects two other providers but forgot to mention the Egyptian provider's file, which is why the passwords leaked in the first place. As it stands, the same mistake can happen again the next time a new provider is added.
- **Suggested fix:** Add a general rule that automatically hides every file whose name ends with credentials, so any current or future provider is protected without anyone having to remember to update the list each time.

