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

```
index=security "failed login"
```

Count failed login attempts by IP address:

```
index=main "Failed password"
| rex "from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats count by src_ip
| sort -count
```

Detect possible brute-force behavior:

```
index=security "failed login"
| stats count by src_ip
| where count > 10
```

## Findings

Multiple failed login attempts were observed from the same IP address within a short time period. This behavior is consistent with a brute-force attack attempting to guess user passwords.

## Screenshots

Screenshots of the Splunk search queries and results are included in this repository.

## Skills Demonstrated

* Log analysis
* Security event investigation
* SIEM usage
* Detection of brute-force login attempts

## Mitigation Recommendations

* Enable account lockout policies
* Implement multi-factor authentication
* Monitor repeated failed login attempts
* Restrict login attempts from suspicious IP addresses

