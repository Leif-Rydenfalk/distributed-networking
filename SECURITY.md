# Security policy

## Reporting a vulnerability

Please report security issues privately to **security@ce-net.com**. Do not open a public issue.

Include what you can: the affected component (control plane, relay leg, path manager, browser client), the version
or commit, steps to reproduce, and the impact you see. We aim to acknowledge reports within 3 business days and to
agree on a disclosure timeline with you.

## Scope

In scope: authentication and admission bypasses, replay or forgery of control, Raft, relay or probe messages,
ways to use a relay or door as a reflector or amplifier, memory-safety issues in parsing, and anything that leaks
keys or lets a stranger reach mesh addresses.

Out of scope: denial of service by an attacker who already holds an admitted node key, and issues in upstream
dependencies that are already public (please report those upstream; tell us if we need to update).

## Supported versions

Only the latest commit on `main` receives fixes before 1.0.
