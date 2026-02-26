#!/usr/bin/env python3
"""
Windows Process Security Analyzer
Defensive security tool for analyzing Windows process logs to detect suspicious behavior
"""

import re
import sys
import json
import logging
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass, field
from collections import defaultdict
import argparse

logger = logging.getLogger(__name__)


@dataclass
class Process:
    """Represents a Windows process with its attributes"""
    name: str
    cpu: Optional[float] = None
    private_bytes: Optional[int] = None
    working_set: Optional[int] = None
    pid: Optional[int] = None
    description: str = ""
    company: str = ""
    parent_pid: Optional[int] = None
    children: List['Process'] = field(default_factory=list)
    depth: int = 0

    def __hash__(self):
        return hash(self.pid) if self.pid else hash(self.name)


class ProcessAnalyzer:
    """Analyzes Windows process logs for security insights"""

    # Configurable thresholds
    HIGH_CPU_THRESHOLD = 90        # percent
    HIGH_MEMORY_BYTES = 1 << 30    # 1 GB
    MAX_TREE_ROOTS = 10
    MAX_TREE_CHILDREN = 5

    # Known legitimate Windows processes and their expected companies
    LEGITIMATE_PROCESSES = {k.lower(): v for k, v in {
        'svchost.exe': 'Microsoft Corporation',
        'csrss.exe': 'Microsoft Corporation',
        'wininit.exe': 'Microsoft Corporation',
        'services.exe': 'Microsoft Corporation',
        'lsass.exe': 'Microsoft Corporation',
        'winlogon.exe': 'Microsoft Corporation',
        'explorer.exe': 'Microsoft Corporation',
        'taskhostw.exe': 'Microsoft Corporation',
        'rundll32.exe': 'Microsoft Corporation',
        'conhost.exe': 'Microsoft Corporation',
        'dllhost.exe': 'Microsoft Corporation',
        'RuntimeBroker.exe': 'Microsoft Corporation',
        'SearchHost.exe': 'Microsoft Corporation',
        'sihost.exe': 'Microsoft Corporation',
        'dasHost.exe': 'Microsoft Corporation',
        'WmiPrvSE.exe': 'Microsoft Corporation',
        'unsecapp.exe': 'Microsoft Corporation',
        'smartscreen.exe': 'Microsoft Corporation',
        'ApplicationFrameHost.exe': 'Microsoft Corporation',
        'backgroundTaskHost.exe': 'Microsoft Corporation',
        'UserOOBEBroker.exe': 'Microsoft Corporation',
        'FileCoAuth.exe': 'Microsoft Corporation',
        'ShellExperienceHost.exe': 'Microsoft Corporation',
        'StartMenuExperienceHost.exe': 'Microsoft Corporation',
        'TextInputHost.exe': 'Microsoft Corporation',
        'Widgets.exe': 'Microsoft Corporation',
        'WindowsPackageManagerServer.exe': 'Microsoft Corporation',
        'ShellHost.exe': 'Microsoft Corporation',
        'CrossDeviceResume.exe': 'Microsoft Corporation',
        'WUDFHost.exe': 'Microsoft Corporation',
    }.items()}

    # Suspicious command-line / description patterns
    SUSPICIOUS_PATTERNS = [
        (r'(?i)cmd\.exe.*powershell', 'Command execution chain'),
        (r'(?i)powershell.*-enc', 'Encoded PowerShell command'),
        (r'(?i)powershell.*-w\s*hidden', 'Hidden PowerShell window'),
        (r'(?i)rundll32.*javascript:', 'JavaScript execution via rundll32'),
        (r'(?i)mshta.*http', 'Remote HTA execution'),
        (r'(?i)regsvr32.*scrobj', 'Squiblydoo attack'),
        (r'(?i)certutil.*-decode', 'Potential file decode operation'),
        (r'(?i)bitsadmin.*download', 'BITS download activity'),
    ]

    # High-risk process names (stored lowercase for fast lookup)
    HIGH_RISK_PROCESSES = frozenset(p.lower() for p in [
        'mimikatz.exe', 'procdump.exe', 'psexec.exe', 'psexesvc.exe',
        'nc.exe', 'netcat.exe', 'tor.exe', 'cryptolocker.exe',
        'wannacry.exe', 'locky.exe', 'cerber.exe',
    ])

    def __init__(self):
        self.processes: List[Process] = []
        self.process_tree: Dict[int, Process] = {}
        self.suspicious_findings: List[Dict] = []

    # ------------------------------------------------------------------
    # Parsing
    # ------------------------------------------------------------------

    def parse_process_log(self, filepath: Path) -> None:
        """Parse process log file and extract process information."""
        try:
            with open(filepath, 'r', encoding='utf-8-sig') as f:
                lines = f.readlines()
        except (OSError, IOError) as e:
            logger.error("Failed to read log file %s: %s", filepath, e)
            raise

        if not lines:
            logger.warning("Log file is empty: %s", filepath)
            return

        # Skip header line
        for i, line in enumerate(lines[1:], 1):
            process = self._parse_line(line, i)
            if process:
                self.processes.append(process)
                if process.pid:
                    self.process_tree[process.pid] = process

    def _parse_line(self, line: str, line_num: int) -> Optional[Process]:
        """Parse a single line from the process log."""
        # Remove line number prefix if present
        line = re.sub(r'^\s*\d+→', '', line)

        # Split by tabs
        parts = line.strip().split('\t')
        if len(parts) < 5:
            return None

        # Extract process name and indentation level
        name_part = parts[0]
        depth = (len(name_part) - len(name_part.lstrip())) // 2
        name = name_part.strip()

        if not name:
            return None

        # Parse CPU usage
        cpu_str = parts[1].strip()
        cpu = None
        if cpu_str and cpu_str not in ('', 'Suspended'):
            try:
                cpu = float(cpu_str.replace('< ', ''))
            except (ValueError, AttributeError):
                logger.debug("Unparseable CPU value on line %d: %r", line_num, cpu_str)

        # Parse memory values
        private_bytes = self._parse_memory(parts[2]) if len(parts) > 2 else None
        working_set = self._parse_memory(parts[3]) if len(parts) > 3 else None

        # Parse PID
        pid = None
        if len(parts) > 4:
            pid_str = parts[4].strip()
            if pid_str and pid_str != 'n/a':
                try:
                    pid = int(pid_str)
                except (ValueError, AttributeError):
                    logger.debug("Unparseable PID on line %d: %r", line_num, pid_str)

        # Parse description and company
        description = parts[5].strip() if len(parts) > 5 else ""
        company = parts[6].strip() if len(parts) > 6 else ""

        return Process(
            name=name,
            cpu=cpu,
            private_bytes=private_bytes,
            working_set=working_set,
            pid=pid,
            description=description,
            company=company,
            depth=depth,
        )

    @staticmethod
    def _parse_memory(mem_str: str) -> Optional[int]:
        """Parse memory string to bytes."""
        if not mem_str:
            return None

        mem_str = mem_str.strip()
        if not mem_str or mem_str == '0 K':
            return 0

        # Remove commas and parse
        mem_str = mem_str.replace(',', '')
        match = re.match(r'([\d.]+)\s*([KMG])?', mem_str)
        if not match:
            return None

        value = float(match.group(1))
        unit = match.group(2)

        multipliers = {'K': 1024, 'M': 1024 ** 2, 'G': 1024 ** 3}
        return int(value * multipliers.get(unit, 1))

    # ------------------------------------------------------------------
    # Tree building
    # ------------------------------------------------------------------

    def build_process_tree(self) -> None:
        """Build parent-child relationships based on indentation."""
        stack: List[Process] = []

        for process in self.processes:
            while stack and stack[-1].depth >= process.depth:
                stack.pop()

            if stack:
                parent = stack[-1]
                parent.children.append(process)
                process.parent_pid = parent.pid

            stack.append(process)

    # ------------------------------------------------------------------
    # Security analysis
    # ------------------------------------------------------------------

    def analyze_security(self) -> None:
        """Perform security analysis on all parsed processes."""
        self.suspicious_findings = []

        for process in self.processes:
            name_lower = process.name.lower()

            # CRITICAL: Known malicious tools
            if name_lower in self.HIGH_RISK_PROCESSES:
                self._add_finding('CRITICAL', 'High-Risk Process', process,
                                  f'Known malicious/hacking tool detected: {process.name}')

            # HIGH / MEDIUM: Masquerading & missing company
            if name_lower in self.LEGITIMATE_PROCESSES:
                expected_company = self.LEGITIMATE_PROCESSES[name_lower]
                if process.company and process.company != expected_company:
                    self._add_finding('HIGH', 'Process Masquerading', process,
                                      f'Process {process.name} has unexpected company: '
                                      f'{process.company} (expected: {expected_company})')
                elif not process.company:
                    self._add_finding('MEDIUM', 'Missing Company Info', process,
                                      f'System process {process.name} missing company information')

            # HIGH: Suspicious command-line patterns
            text_to_scan = ' '.join(filter(None, [process.name, process.description]))
            for pattern, description in self.SUSPICIOUS_PATTERNS:
                if re.search(pattern, text_to_scan):
                    self._add_finding('HIGH', 'Suspicious Pattern', process,
                                      f'{description}: {process.name}')

            # MEDIUM: High CPU
            if process.cpu is not None and process.cpu > self.HIGH_CPU_THRESHOLD:
                self._add_finding('MEDIUM', 'High CPU Usage', process,
                                  f'Process consuming {process.cpu:.1f}% CPU')

            # LOW: High memory
            if process.working_set and process.working_set > self.HIGH_MEMORY_BYTES:
                mem_gb = process.working_set / (1024 ** 3)
                self._add_finding('LOW', 'High Memory Usage', process,
                                  f'Process using {mem_gb:.1f} GB of memory')

            # LOW: Unsigned (non-system, non-legitimate)
            if (not process.company
                    and not process.name.startswith('System')
                    and name_lower not in self.LEGITIMATE_PROCESSES):
                self._add_finding('LOW', 'Unsigned Process', process,
                                  f'Process {process.name} has no company signature')

    def check_process_chains(self) -> None:
        """Check for suspicious process spawning chains."""
        suspicious_chains = frozenset({
            ('winword.exe', 'cmd.exe'),
            ('excel.exe', 'cmd.exe'),
            ('outlook.exe', 'cmd.exe'),
            ('winword.exe', 'powershell.exe'),
            ('excel.exe', 'powershell.exe'),
            ('outlook.exe', 'powershell.exe'),
            ('wmiprvse.exe', 'powershell.exe'),
            ('mshta.exe', 'powershell.exe'),
            ('rundll32.exe', 'cmd.exe'),
        })

        for process in self.processes:
            if not process.children:
                continue

            parent_lower = process.name.lower()
            for child in process.children:
                if (parent_lower, child.name.lower()) in suspicious_chains:
                    self._add_finding(
                        'HIGH', 'Suspicious Process Chain', child,
                        f'Potentially malicious process spawning: '
                        f'{process.name} (PID: {process.pid}) spawned '
                        f'{child.name} (PID: {child.pid})',
                        process_label=f'{process.name} -> {child.name}',
                    )

    def _add_finding(self, severity: str, finding_type: str, process: Process,
                     description: str, *, process_label: Optional[str] = None) -> None:
        """Helper to append a finding dict."""
        self.suspicious_findings.append({
            'severity': severity,
            'type': finding_type,
            'process': process_label or process.name,
            'pid': process.pid,
            'description': description,
        })

    # ------------------------------------------------------------------
    # Reporting
    # ------------------------------------------------------------------

    def generate_report(self) -> str:
        """Generate security analysis report."""
        report: List[str] = []
        report.append("=" * 80)
        report.append("WINDOWS PROCESS SECURITY ANALYSIS REPORT")
        report.append("=" * 80)
        report.append("")

        # Summary statistics
        report.append("SUMMARY STATISTICS")
        report.append("-" * 40)
        report.append(f"Total processes analyzed: {len(self.processes)}")
        report.append(f"Suspicious findings: {len(self.suspicious_findings)}")

        # Count by severity
        severity_counts: Dict[str, int] = defaultdict(int)
        for finding in self.suspicious_findings:
            severity_counts[finding['severity']] += 1

        report.append("")
        report.append("Findings by severity:")
        for severity in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW'):
            report.append(f"  {severity}: {severity_counts.get(severity, 0)}")

        # Process statistics
        report.append("")
        report.append("PROCESS STATISTICS")
        report.append("-" * 40)

        # Top CPU consumers
        cpu_processes = sorted(
            (p for p in self.processes if p.cpu is not None),
            key=lambda x: x.cpu or 0, reverse=True,
        )
        report.append("Top 5 CPU Consumers:")
        for proc in cpu_processes[:5]:
            report.append(f"  {proc.name}: {proc.cpu:.2f}% (PID: {proc.pid})")

        # Top memory consumers
        mem_processes = sorted(
            (p for p in self.processes if p.working_set),
            key=lambda x: x.working_set or 0, reverse=True,
        )
        report.append("")
        report.append("Top 5 Memory Consumers:")
        for proc in mem_processes[:5]:
            mem_mb = (proc.working_set or 0) / (1024 * 1024)
            report.append(f"  {proc.name}: {mem_mb:.1f} MB (PID: {proc.pid})")

        # Suspicious findings
        if self.suspicious_findings:
            report.append("")
            report.append("SECURITY FINDINGS")
            report.append("-" * 40)

            findings_by_severity: Dict[str, List[Dict]] = defaultdict(list)
            for finding in self.suspicious_findings:
                findings_by_severity[finding['severity']].append(finding)

            for severity in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW'):
                findings = findings_by_severity.get(severity, [])
                if findings:
                    report.append("")
                    report.append(f"[{severity}] Findings:")
                    for finding in findings:
                        report.append(f"  * {finding['type']}: {finding['process']}")
                        report.append(f"    {finding['description']}")
                        if finding['pid']:
                            report.append(f"    PID: {finding['pid']}")
        else:
            report.append("")
            report.append("No suspicious findings detected.")

        # Process tree
        report.append("")
        report.append("PROCESS TREE")
        report.append("-" * 40)

        root_processes = [p for p in self.processes if p.depth == 0]
        for root in root_processes[:self.MAX_TREE_ROOTS]:
            self._add_process_tree_to_report(root, report)

        report.append("")
        report.append("=" * 80)
        report.append("END OF REPORT")
        report.append("=" * 80)

        return "\n".join(report)

    def _add_process_tree_to_report(self, process: Process,
                                    report: List[str], indent: int = 0) -> None:
        """Recursively add process tree to report."""
        prefix = "  " * indent + "|- " if indent > 0 else ""
        info = f"{prefix}{process.name}"
        if process.pid:
            info += f" (PID: {process.pid})"
        if process.company:
            info += f" [{process.company}]"
        report.append(info)

        for child in process.children[:self.MAX_TREE_CHILDREN]:
            self._add_process_tree_to_report(child, report, indent + 1)

        remaining = len(process.children) - self.MAX_TREE_CHILDREN
        if remaining > 0:
            report.append("  " * (indent + 1) + f"... and {remaining} more children")

    # ------------------------------------------------------------------
    # Export
    # ------------------------------------------------------------------

    def export_json(self, filepath: Path) -> None:
        """Export analysis results to JSON."""
        data = {
            'summary': {
                'total_processes': len(self.processes),
                'suspicious_findings': len(self.suspicious_findings),
            },
            'findings': self.suspicious_findings,
            'processes': [
                {
                    'name': p.name,
                    'pid': p.pid,
                    'cpu': p.cpu,
                    'memory_mb': round(p.working_set / (1024 * 1024), 2)
                                 if p.working_set else None,
                    'company': p.company,
                    'description': p.description,
                }
                for p in self.processes
            ],
        }

        try:
            with open(filepath, 'w') as f:
                json.dump(data, f, indent=2)
        except (OSError, IOError) as e:
            logger.error("Failed to write JSON export %s: %s", filepath, e)
            raise


# ----------------------------------------------------------------------
# CLI entry point
# ----------------------------------------------------------------------

def main() -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Analyze Windows process logs for security threats',
    )
    parser.add_argument('logfile', type=Path, help='Path to process log file')
    parser.add_argument('--json', type=Path, dest='json_out',
                        help='Export results to JSON file')
    parser.add_argument('--output', type=Path, help='Save report to file')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Enable verbose/debug logging')

    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format='%(levelname)s: %(message)s',
    )

    if not args.logfile.exists():
        logger.error("Log file not found: %s", args.logfile)
        return 1

    # Create analyzer and process log
    analyzer = ProcessAnalyzer()

    logger.info("Parsing process log: %s", args.logfile)
    analyzer.parse_process_log(args.logfile)

    logger.info("Building process tree (%d processes)...", len(analyzer.processes))
    analyzer.build_process_tree()

    logger.info("Analyzing security...")
    analyzer.analyze_security()
    analyzer.check_process_chains()

    # Generate report
    report = analyzer.generate_report()

    if args.output:
        with open(args.output, 'w') as f:
            f.write(report)
        logger.info("Report saved to: %s", args.output)
    else:
        print(report)

    # Export JSON if requested
    if args.json_out:
        analyzer.export_json(args.json_out)
        logger.info("JSON results exported to: %s", args.json_out)

    return 0


if __name__ == '__main__':
    sys.exit(main())
