"""
SAST Engine Orchestrator for KernelSpy Scanner.
Integrates external static analysis tools via CLI/API:
- Semgrep: Multi-language pattern-based security scanning
- Trivy: Dependency vulnerability scanning
- SonarScanner: Code quality and security analysis

Results are unified into KernelSpy Finding format.
"""
import json
import os
import re
import shutil
import subprocess
import tempfile
from typing import List, Optional, Dict, Callable
from dataclasses import dataclass

from ..models import Finding


@dataclass
class SASTConfig:
    """Configuration for SAST engine orchestration."""
    semgrep_enabled: bool = True
    semgrep_paths: Optional[List[str]] = None
    semgrep_rulesets: Optional[List[str]] = None
    trivy_enabled: bool = True
    sonar_enabled: bool = True
    timeout: int = 300  # seconds per tool


class SemgrepScanner:
    """Semgrep integration for pattern-based multi-language scanning."""

    RULESETS = {
        'security': 'p/security-audit',
        'secrets': 'p/secrets',
        'owasp': 'p/owasp-top-ten',
        'cwe': 'p/cwe-top-25',
        'typescript': 'p/typescript',
        'python': 'p/python',
        'java': 'p/java',
        'javascript': 'p/javascript',
        'go': 'p/go',
        'php': 'p/php',
        'ruby': 'p/ruby',
        'rust': 'p/rust',
        'kotlin': 'p/kotlin',
        'swift': 'p/swift',
        'generic': 'p/generic',
    }

    def __init__(self):
        self._available = shutil.which('semgrep') is not None

    @property
    def available(self) -> bool:
        return self._available

    def scan(self, folder: str, progress_callback: Optional[Callable] = None,
             cancel_check: Optional[Callable] = None) -> List[Finding]:
        """Run Semgrep on a folder and return findings."""
        if not self._available:
            return []

        findings = []
        rulesets = ['p/security-audit', 'p/secrets', 'p/owasp-top-ten', 'p/cwe-top-25']

        cmd = [
            'semgrep', '--json', '--quiet',
            '--config', 'auto',
            '--severity', 'ERROR', '--severity', 'WARNING', '--severity', 'INFO',
            '--timeout', '30',
            '--max-target-bytes', '1000000',
            folder,
        ]

        try:
            if progress_callback:
                progress_callback(-1, "Running Semgrep scan...")

            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=300,
                encoding='utf-8', errors='ignore',
            )

            if proc.stdout:
                data = json.loads(proc.stdout)
                for result in data.get('results', []):
                    severity = result.get('extra', {}).get('severity', 'WARNING').upper()
                    if severity not in ('CRITICAL', 'ERROR'):
                        severity_map = {'ERROR': 'HIGH', 'WARNING': 'MEDIUM', 'INFO': 'LOW'}
                        severity = severity_map.get(severity, 'MEDIUM')

                    findings.append(Finding(
                        file=os.path.relpath(result.get('path', ''), folder),
                        line=result.get('start', {}).get('line', 0),
                        type=f"Semgrep: {result.get('check_id', 'unknown')}",
                        severity=severity,
                        snippet=result.get('extra', {}).get('lines', '')[:120],
                        description=result.get('extra', {}).get('message', ''),
                        category="INJECTION",
                        analyzer="semgrep",
                    ))
        except subprocess.TimeoutExpired:
            pass
        except Exception:
            pass

        return findings


class TrivyScanner:
    """Trivy integration for dependency vulnerability scanning."""

    def __init__(self):
        self._available = shutil.which('trivy') is not None

    @property
    def available(self) -> bool:
        return self._available

    def scan(self, folder: str, progress_callback: Optional[Callable] = None) -> List[Finding]:
        """Run Trivy filesystem scan and return findings."""
        if not self._available:
            return []

        findings = []

        cmd = [
            'trivy', 'fs', '--format', 'json',
            '--severity', 'CRITICAL,HIGH,MEDIUM',
            '--scanners', 'vuln',
            '--timeout', '5m',
            folder,
        ]

        try:
            if progress_callback:
                progress_callback(-1, "Running Trivy dependency scan...")

            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=300,
                encoding='utf-8', errors='ignore',
            )

            if proc.stdout:
                data = json.loads(proc.stdout)
                for result in data.get('Results', []):
                    for vuln in result.get('Vulnerabilities', []):
                        severity = vuln.get('Severity', 'MEDIUM').upper()
                        findings.append(Finding(
                            file=os.path.relpath(result.get('Target', ''), folder),
                            line=0,
                            type=f"Trivy: {vuln.get('VulnerabilityID', '')}",
                            severity=severity,
                            snippet=f"{vuln.get('PkgName', '')} {vuln.get('InstalledVersion', '')}",
                            description=(
                                f"{vuln.get('Title', vuln.get('Description', '')[:100])}. "
                                f"Fixed in: {vuln.get('FixedVersion', 'N/A')}"
                            ),
                            category="DEPENDENCY",
                            analyzer="trivy",
                        ))
        except subprocess.TimeoutExpired:
            pass
        except Exception:
            pass

        return findings


class SonarScanner:
    """SonarScanner integration for code quality and security analysis."""

    def __init__(self):
        self._available = shutil.which('sonar-scanner') is not None

    @property
    def available(self) -> bool:
        return self._available

    def scan(self, folder: str, project_key: str = "kernelspy_scan",
             progress_callback: Optional[Callable] = None) -> List[Finding]:
        """Run SonarScanner and return findings."""
        if not self._available:
            return []

        findings = []

        # Create sonar-project.properties
        config_path = os.path.join(folder, 'sonar-project.properties')
        created_config = False
        if not os.path.exists(config_path):
            try:
                with open(config_path, 'w', encoding='utf-8') as f:
                    f.write(f"sonar.projectKey={project_key}\n")
                    f.write(f"sonar.sources=.\n")
                    f.write(f"sonar.exclusions=**/node_modules/**,**/vendor/**,**/.git/**\n")
                created_config = True
            except Exception:
                return []

        cmd = ['sonar-scanner', '-Dsonar.analysis.mode=preview']

        try:
            if progress_callback:
                progress_callback(-1, "Running SonarScanner analysis...")

            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=300,
                cwd=folder, encoding='utf-8', errors='ignore',
            )

            # Parse SARIF output if available
            sarif_path = os.path.join(folder, '.scannerwork', 'report.json')
            if os.path.exists(sarif_path):
                with open(sarif_path, 'r', encoding='utf-8') as f:
                    sarif_data = json.load(f)
                    for run in sarif_data.get('runs', []):
                        for result in run.get('results', []):
                            loc = result.get('locations', [{}])[0]
                            phys = loc.get('physicalLocation', {})
                            line = phys.get('region', {}).get('startLine', 0)
                            findings.append(Finding(
                                file=os.path.relpath(
                                    phys.get('artifactLocation', {}).get('uri', ''), folder),
                                line=line,
                                type=f"Sonar: {result.get('ruleId', 'unknown')}",
                                severity=_map_sonar_severity(result.get('level', 'warning')),
                                snippet="",
                                description=result.get('message', {}).get('text', ''),
                                category="QUALITY",
                                analyzer="sonar",
                            ))
        except subprocess.TimeoutExpired:
            pass
        except Exception:
            pass
        finally:
            # Clean up generated config
            if created_config and os.path.exists(config_path):
                try:
                    os.remove(config_path)
                except Exception:
                    pass

        return findings


def _map_sonar_severity(level: str) -> str:
    """Map SonarQube severity levels to KernelSpy severity."""
    return {
        'blocker': 'CRITICAL',
        'critical': 'HIGH',
        'major': 'MEDIUM',
        'minor': 'LOW',
        'info': 'LOW',
        'error': 'HIGH',
        'warning': 'MEDIUM',
        'note': 'LOW',
    }.get(level.lower(), 'MEDIUM')


class SASTOrchestrator:
    """Orchestrates multiple SAST engines and unifies results."""

    def __init__(self, config: Optional[SASTConfig] = None):
        self.config = config or SASTConfig()
        self._semgrep = SemgrepScanner()
        self._trivy = TrivyScanner()
        self._sonar = SonarScanner()

    @property
    def available_engines(self) -> Dict[str, bool]:
        """Get availability status of each engine."""
        return {
            'semgrep': self._semgrep.available,
            'trivy': self._trivy.available,
            'sonar': self._sonar.available,
        }

    def scan_all(self, folder: str, progress_callback: Optional[Callable] = None,
                 cancel_check: Optional[Callable] = None) -> List[Finding]:
        """Run all enabled SAST engines and return unified findings."""
        all_findings = []

        if self.config.semgrep_enabled and self._semgrep.available:
            if cancel_check and cancel_check():
                return all_findings
            all_findings.extend(self._semgrep.scan(folder, progress_callback, cancel_check))

        if self.config.trivy_enabled and self._trivy.available:
            if cancel_check and cancel_check():
                return all_findings
            all_findings.extend(self._trivy.scan(folder, progress_callback))

        if self.config.sonar_enabled and self._sonar.available:
            if cancel_check and cancel_check():
                return all_findings
            all_findings.extend(self._sonar.scan(folder, progress_callback=progress_callback))

        return all_findings

    def scan_semgrep(self, folder: str, progress_callback: Optional[Callable] = None,
                     cancel_check: Optional[Callable] = None) -> List[Finding]:
        """Run only Semgrep."""
        return self._semgrep.scan(folder, progress_callback, cancel_check)

    def scan_trivy(self, folder: str, progress_callback: Optional[Callable] = None) -> List[Finding]:
        """Run only Trivy."""
        return self._trivy.scan(folder, progress_callback)

    def scan_sonar(self, folder: str, progress_callback: Optional[Callable] = None) -> List[Finding]:
        """Run only SonarScanner."""
        return self._sonar.scan(folder, progress_callback=progress_callback)


# Global singleton
_sast_orchestrator: Optional[SASTOrchestrator] = None


def get_sast_orchestrator() -> SASTOrchestrator:
    """Get or create the global SAST orchestrator."""
    global _sast_orchestrator
    if _sast_orchestrator is None:
        _sast_orchestrator = SASTOrchestrator()
    return _sast_orchestrator
