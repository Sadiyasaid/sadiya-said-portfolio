# Suspicious Azure AD Sign-In Detection

## Overview
This project demonstrates a defensive detection use case to identify potentially compromised cloud accounts using Azure AD sign-in telemetry in Microsoft Sentinel.

---

## Threat Scenario
An attacker gains access to valid credentials and successfully authenticates from an unusual location or device, bypassing basic authentication controls.

---

## Data Sources
- Azure AD Sign-In Logs

---

## Detection Logic (KQL)
```kql
SigninLogs
| where ResultType == 0
| where RiskLevelDuringSignIn in ("medium", "high")
| project TimeGenerated, UserPrincipalName, IPAddress, Location, AppDisplayName, RiskLevelDuringSignIn
