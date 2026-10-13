# Windows Logon Detection Report

Events analyzed: **12**  
Alerts generated: **2**

**Scope:** Automated triage of exported lab events. An alert is not proof of compromise.

## Alert 1: HIGH - success_after_repeated_failures

- Source IP: `198.51.100.23`
- Account: `lab-user`
- Failed logons recorded in alert: 5
- First failure: 2026-10-10T09:00:00+00:00
- Last failure: 2026-10-10T09:04:00+00:00
- Subsequent successful logon: 2026-10-10T09:06:00+00:00
- Interpretation: A successful logon followed repeated failures for the same source/account. Investigate; compromise is not confirmed.

## Alert 2: MEDIUM - repeated_failed_logons

- Source IP: `203.0.113.15`
- Account: `other-user`
- Failed logons recorded in alert: 5
- First failure: 2026-10-10T10:00:00+00:00
- Last failure: 2026-10-10T10:04:00+00:00
- Subsequent successful logon: Not observed
- Interpretation: Repeated failed logons warrant investigation; they do not prove an attack.

## Suggested analyst follow-up

1. Verify timestamps, account context, and whether events are expected.
2. Check login type, workstation, MFA outcomes, and nearby events if available.
3. Escalate through your lab's incident-response process if warranted.
