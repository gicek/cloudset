# Security policy

Please report vulnerabilities privately through GitHub's "Report a vulnerability" button on the repository's Security
tab. Do not open a public issue. You will get a reply within a week.

Relevant reports include ways to make the crate send credentials to another origin, follow a redirect it should refuse,
accept a callback that does not belong to the sign-in, leak tokens or passwords through `Debug` or errors, or exhaust
memory or CPU with crafted responses.

Only the latest released version receives fixes.
