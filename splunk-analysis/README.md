# Splunk Log Analysis Lab

## Objective

The goal of this lab is to analyze system authentication logs using Splunk to detect suspicious login activity.

## Tool Used

Splunk (SIEM)

## Scenario

A system administrator suspects that someone is attempting to brute-force login credentials on a server. Log data was ingested into Splunk to investigate failed login attempts.

## Data Source

Authentication logs from a simulated lab environment.

## Investigation Steps

1. Ingest authentication logs into Splunk.
2. Search for failed login attempts.
3. Identify IP addresses responsible for repeated failures.
4. Determine if the pattern indicates a brute-force attack.

## Splunk Queries Used

Search for failed logins:
(SCREENSHOT 1)
```
index=security "failed login"
```

Count failed login attempts by IP address:
(SCREENSHOT 2)
```
index=main "Failed password"
| rex "from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats count by src_ip
| sort -count
```

Detect  usernames attackers tried:
(SCREENSHOT 3)
```
index=main "Failed password"
| rex "user (?<username>\w+)"
| stats count by username
| sort -count
```

Detect  IP → which usernames it attacked:
(SCREENSHOT 4)
---
index=main "Failed password"
| rex "from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| rex "user (?<username>\w+)"
| stats count by src_ip username
| sort -count


## Screenshots

Screenshots of the Splunk search queries and results are included in this repository.

## Skills Demonstrated

* Log analysis
* Security event investigation
* SIEM usage
* Detection of brute-force login attempts
* Threat analysis
* Basic incident reporting

  
## Mitigation Recommendations
* Enable account lockout policies
* Implement multi-factor authentication
* Monitor repeated failed login attempts
* Restrict login attempts from suspicious IP addresses
* Restrict SSH access using firewall rules or allowlists
  
