# Windows Process Security Analyzer

A defensive security tool for analyzing Windows process logs to detect suspicious behavior, malicious processes, and potential security threats.

## Features

- **Process Tree Analysis**: Builds parent-child relationships from process logs
- **Security Detection**: Identifies suspicious processes and behaviors including:
  - Known malicious/hacking tools
  - Process masquerading (legitimate processes with wrong signatures)
  - Suspicious process chains (e.g., Office apps spawning cmd/PowerShell)
  - High CPU/memory usage anomalies
  - Unsigned processes
- **Comprehensive Reporting**: Generates detailed security reports with severity levels
- **JSON Export**: Export analysis results for further processing

## Installation

Requires Python 3.8+ (Python 3.11+ recommended). For Python < 3.11, install the
`tomli` package:

```bash
pip install -r python/requirements.txt
```

## Usage

Basic usage:
```bash
python process_analyzer.py <logfile>
```

Save report to file:
```bash
python process_analyzer.py <logfile> --output report.txt
```

Export to JSON:
```bash
python process_analyzer.py <logfile> --json results.json
```

Verbose/debug output:
```bash
python process_analyzer.py <logfile> -v
```

## Input Format

The analyzer expects process logs in tab-separated format with the following columns:
- Process name (with indentation showing hierarchy)
- CPU usage
- Private Bytes
- Working Set
- PID
- Description
- Company Name

## Security Checks

The analyzer performs the following security checks:

### Critical Severity
- Known malicious tools (mimikatz, psexec, cryptolocker, etc.)

### High Severity
- Process masquerading (system processes with incorrect signatures)
- Suspicious process chains (Office → cmd/PowerShell)
- Suspicious command-line patterns (encoded PowerShell, Squiblydoo, BITS abuse, etc.)

### Medium Severity
- Missing company information for system processes
- Extremely high CPU usage (>90%)

### Low Severity
- Unsigned processes
- High memory usage (>1GB)

## Example Output

```
================================================================================
WINDOWS PROCESS SECURITY ANALYSIS REPORT
================================================================================

SUMMARY STATISTICS
----------------------------------------
Total processes analyzed: 500
Suspicious findings: 25

Findings by severity:
  CRITICAL: 0
  HIGH: 2
  MEDIUM: 5
  LOW: 18

[HIGH] Findings:
  • Process Masquerading: svchost.exe
    Process svchost.exe has unexpected company: Unknown (expected: Microsoft Corporation)
    PID: 12345
```

## Security Best Practices

When reviewing the analysis results:

1. **Investigate Critical findings immediately** - These indicate known malicious tools
2. **Verify High severity findings** - Check if processes are legitimate or compromised
3. **Review Medium findings** - May indicate configuration issues or suspicious activity
4. **Monitor Low severity findings** - Track patterns over time

## License

This tool is for defensive security purposes only. Use responsibly for analyzing and securing Windows systems.