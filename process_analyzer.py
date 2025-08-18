#!/usr/bin/env python3
"""
Windows Process Security Analyzer
Defensive security tool for analyzing Windows process logs to detect suspicious behavior
"""

import re
import json
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass, field
from collections import defaultdict
import argparse


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
    
    # Known legitimate Windows processes and their expected companies
    LEGITIMATE_PROCESSES = {
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
    }
    
    # Suspicious process indicators
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
    
    # High-risk process names
    HIGH_RISK_PROCESSES = [
        'mimikatz.exe', 'procdump.exe', 'psexec.exe', 'psexesvc.exe',
        'nc.exe', 'netcat.exe', 'tor.exe', 'cryptolocker.exe',
        'wannacry.exe', 'locky.exe', 'cerber.exe'
    ]
    
    def __init__(self):
        self.processes: List[Process] = []
        self.process_tree: Dict[int, Process] = {}
        self.suspicious_findings: List[Dict] = []
        
    def parse_process_log(self, filepath: Path) -> None:
        """Parse process log file and extract process information"""
        with open(filepath, 'r', encoding='utf-8-sig') as f:
            lines = f.readlines()
        
        if not lines:
            return
            
        # Skip header line
        for i, line in enumerate(lines[1:], 1):
            process = self._parse_line(line, i)
            if process:
                self.processes.append(process)
                if process.pid:
                    self.process_tree[process.pid] = process
    
    def _parse_line(self, line: str, line_num: int) -> Optional[Process]:
        """Parse a single line from the process log"""
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
        if cpu_str and cpu_str not in ['', 'Suspended']:
            try:
                cpu = float(cpu_str.replace('< ', ''))
            except:
                pass
        
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
                except:
                    pass
        
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
            depth=depth
        )
    
    def _parse_memory(self, mem_str: str) -> Optional[int]:
        """Parse memory string to bytes"""
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
        
        if unit == 'K':
            return int(value * 1024)
        elif unit == 'M':
            return int(value * 1024 * 1024)
        elif unit == 'G':
            return int(value * 1024 * 1024 * 1024)
        else:
            return int(value)
    
    def build_process_tree(self) -> None:
        """Build parent-child relationships based on indentation"""
        stack = []
        
        for process in self.processes:
            # Find parent based on depth
            while stack and stack[-1].depth >= process.depth:
                stack.pop()
            
            if stack:
                parent = stack[-1]
                parent.children.append(process)
                process.parent_pid = parent.pid
            
            stack.append(process)
    
    def analyze_security(self) -> None:
        """Perform security analysis on processes"""
        self.suspicious_findings = []
        
        # Check for suspicious process names
        for process in self.processes:
            # Check against high-risk processes
            if process.name.lower() in [p.lower() for p in self.HIGH_RISK_PROCESSES]:
                self.suspicious_findings.append({
                    'severity': 'CRITICAL',
                    'type': 'High-Risk Process',
                    'process': process.name,
                    'pid': process.pid,
                    'description': f'Known malicious/hacking tool detected: {process.name}'
                })
            
            # Check for masquerading processes
            if process.name in self.LEGITIMATE_PROCESSES:
                expected_company = self.LEGITIMATE_PROCESSES[process.name]
                if process.company and process.company != expected_company:
                    self.suspicious_findings.append({
                        'severity': 'HIGH',
                        'type': 'Process Masquerading',
                        'process': process.name,
                        'pid': process.pid,
                        'description': f'Process {process.name} has unexpected company: {process.company} (expected: {expected_company})'
                    })
                elif not process.company:
                    self.suspicious_findings.append({
                        'severity': 'MEDIUM',
                        'type': 'Missing Company Info',
                        'process': process.name,
                        'pid': process.pid,
                        'description': f'System process {process.name} missing company information'
                    })
            
            # Check for suspicious CPU usage
            if process.cpu and process.cpu > 90:
                self.suspicious_findings.append({
                    'severity': 'MEDIUM',
                    'type': 'High CPU Usage',
                    'process': process.name,
                    'pid': process.pid,
                    'description': f'Process consuming {process.cpu:.1f}% CPU'
                })
            
            # Check for suspicious memory usage
            if process.working_set and process.working_set > 1024 * 1024 * 1024:  # > 1GB
                mem_gb = process.working_set / (1024 * 1024 * 1024)
                self.suspicious_findings.append({
                    'severity': 'LOW',
                    'type': 'High Memory Usage',
                    'process': process.name,
                    'pid': process.pid,
                    'description': f'Process using {mem_gb:.1f} GB of memory'
                })
            
            # Check for unsigned processes
            if not process.company and not process.name.startswith('System'):
                self.suspicious_findings.append({
                    'severity': 'LOW',
                    'type': 'Unsigned Process',
                    'process': process.name,
                    'pid': process.pid,
                    'description': f'Process {process.name} has no company signature'
                })
    
    def check_process_chains(self) -> None:
        """Check for suspicious process spawning chains"""
        # Look for suspicious parent-child relationships
        suspicious_chains = [
            ('winword.exe', 'cmd.exe'),
            ('excel.exe', 'cmd.exe'),
            ('outlook.exe', 'cmd.exe'),
            ('winword.exe', 'powershell.exe'),
            ('excel.exe', 'powershell.exe'),
            ('outlook.exe', 'powershell.exe'),
            ('wmiprvse.exe', 'powershell.exe'),
            ('mshta.exe', 'powershell.exe'),
            ('rundll32.exe', 'cmd.exe'),
        ]
        
        for process in self.processes:
            if not process.children:
                continue
                
            for child in process.children:
                for parent_name, child_name in suspicious_chains:
                    if (process.name.lower() == parent_name.lower() and 
                        child.name.lower() == child_name.lower()):
                        self.suspicious_findings.append({
                            'severity': 'HIGH',
                            'type': 'Suspicious Process Chain',
                            'process': f'{process.name} -> {child.name}',
                            'pid': child.pid,
                            'description': f'Potentially malicious process spawning: {process.name} (PID: {process.pid}) spawned {child.name} (PID: {child.pid})'
                        })
    
    def generate_report(self) -> str:
        """Generate security analysis report"""
        report = []
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
        severity_counts = defaultdict(int)
        for finding in self.suspicious_findings:
            severity_counts[finding['severity']] += 1
        
        report.append("")
        report.append("Findings by severity:")
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            count = severity_counts.get(severity, 0)
            report.append(f"  {severity}: {count}")
        
        # Process statistics
        report.append("")
        report.append("PROCESS STATISTICS")
        report.append("-" * 40)
        
        # Top CPU consumers
        cpu_processes = [p for p in self.processes if p.cpu is not None]
        cpu_processes.sort(key=lambda x: x.cpu or 0, reverse=True)
        
        report.append("Top 5 CPU Consumers:")
        for proc in cpu_processes[:5]:
            report.append(f"  {proc.name}: {proc.cpu:.2f}% (PID: {proc.pid})")
        
        # Top memory consumers
        mem_processes = [p for p in self.processes if p.working_set]
        mem_processes.sort(key=lambda x: x.working_set or 0, reverse=True)
        
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
            
            # Sort by severity
            findings_by_severity = defaultdict(list)
            for finding in self.suspicious_findings:
                findings_by_severity[finding['severity']].append(finding)
            
            for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
                findings = findings_by_severity.get(severity, [])
                if findings:
                    report.append("")
                    report.append(f"[{severity}] Findings:")
                    for finding in findings:
                        report.append(f"  • {finding['type']}: {finding['process']}")
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
        
        # Find root processes (depth 0)
        root_processes = [p for p in self.processes if p.depth == 0]
        for root in root_processes[:10]:  # Limit to first 10 root processes
            self._add_process_tree_to_report(root, report)
        
        report.append("")
        report.append("=" * 80)
        report.append("END OF REPORT")
        report.append("=" * 80)
        
        return "\n".join(report)
    
    def _add_process_tree_to_report(self, process: Process, report: List[str], indent: int = 0) -> None:
        """Recursively add process tree to report"""
        prefix = "  " * indent + "├─ " if indent > 0 else ""
        info = f"{prefix}{process.name}"
        if process.pid:
            info += f" (PID: {process.pid})"
        if process.company:
            info += f" [{process.company}]"
        report.append(info)
        
        for child in process.children[:5]:  # Limit children display
            self._add_process_tree_to_report(child, report, indent + 1)
        
        if len(process.children) > 5:
            report.append("  " * (indent + 1) + f"... and {len(process.children) - 5} more children")
    
    def export_json(self, filepath: Path) -> None:
        """Export analysis results to JSON"""
        data = {
            'summary': {
                'total_processes': len(self.processes),
                'suspicious_findings': len(self.suspicious_findings)
            },
            'findings': self.suspicious_findings,
            'processes': [
                {
                    'name': p.name,
                    'pid': p.pid,
                    'cpu': p.cpu,
                    'memory_mb': p.working_set / (1024 * 1024) if p.working_set else None,
                    'company': p.company,
                    'description': p.description
                }
                for p in self.processes
            ]
        }
        
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='Analyze Windows process logs for security threats'
    )
    parser.add_argument(
        'logfile',
        type=Path,
        help='Path to process log file'
    )
    parser.add_argument(
        '--json',
        type=Path,
        help='Export results to JSON file'
    )
    parser.add_argument(
        '--output',
        type=Path,
        help='Save report to file'
    )
    
    args = parser.parse_args()
    
    if not args.logfile.exists():
        print(f"Error: Log file '{args.logfile}' not found")
        return 1
    
    # Create analyzer and process log
    analyzer = ProcessAnalyzer()
    print(f"Parsing process log: {args.logfile}")
    analyzer.parse_process_log(args.logfile)
    
    print(f"Building process tree...")
    analyzer.build_process_tree()
    
    print(f"Analyzing security...")
    analyzer.analyze_security()
    analyzer.check_process_chains()
    
    # Generate report
    report = analyzer.generate_report()
    
    # Output report
    if args.output:
        with open(args.output, 'w') as f:
            f.write(report)
        print(f"Report saved to: {args.output}")
    else:
        print("\n" + report)
    
    # Export JSON if requested
    if args.json:
        analyzer.export_json(args.json)
        print(f"JSON results exported to: {args.json}")
    
    return 0


if __name__ == '__main__':
    exit(main())