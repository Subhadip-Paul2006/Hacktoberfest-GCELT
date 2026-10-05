"""Host security auditor: active listening ports and malware indicators for NSAT."""

from pathlib import Path
from nsat.core.surface import SecuritySurface
from nsat.normalization.models import CanonicalFinding, FindingEvidence
from nsat.scanners.base import BaseScanner


# Suspicious import patterns indicating keyboard hooking / spyware behavior
SUSPICIOUS_HOOK_PATTERNS = [
    ("pynput", "Keyboard/mouse hook library — potential keylogger"),
    ("xdotool", "X11 input simulation — potential covert input injection"),
    ("SetWindowsHookEx", "Win32 global keyboard/mouse hook — potential keylogger"),
    ("GetAsyncKeyState", "Win32 low-level key polling — potential keylogger"),
    ("pyautogui", "Screen/input automation library — potential surveillance tool"),
    ("win32api.GetAsyncKeyState", "Low-level Win32 key state polling"),
]

# Ports that are commonly suspicious if listening on all interfaces unexpectedly
SUSPICIOUS_PORTS = {
    4444: "Metasploit default listener",
    1337: "Common backdoor port",
    31337: "Back Orifice / l33t backdoor",
    9999: "Common reverse shell default",
    8888: "Common debug port exposed externally",
    6666: "IRC / RAT common port",
}


class HostScanner(BaseScanner):
    """
    Inspects local host for active listening ports (via psutil) and
    suspicious import patterns in source code (malware indicator detection).
    """

    @property
    def scanner_name(self) -> str:
        return "host_scanner"

    def scan(self, target_path: Path, surface: SecuritySurface) -> list[CanonicalFinding]:
        findings: list[CanonicalFinding] = []
        seq = 1

        # Domain J: Inspect active local listening ports
        seq, findings = self._check_listening_ports(findings, seq)

        # Domain K: Detect suspicious keyboard hook imports in source
        seq, findings = self._check_malware_indicators(target_path, findings, seq)

        return findings

    def _check_listening_ports(self, findings: list, seq: int):
        """Use psutil to enumerate locally listening sockets."""
        try:
            import psutil
            listening_connections = [
                c for c in psutil.net_connections(kind="inet")
                if c.status == psutil.CONN_LISTEN
            ]
            for conn in listening_connections:
                if conn.laddr is None:
                    continue
                host = conn.laddr.ip
                port = conn.laddr.port
                pid = conn.pid

                sev = "LOW"
                hint = ""

                # Flag suspicious ports
                if port in SUSPICIOUS_PORTS:
                    sev = "HIGH"
                    hint = f" — {SUSPICIOUS_PORTS[port]}"

                # Flag externally reachable listeners
                elif host in ("0.0.0.0", "::"):
                    sev = "MEDIUM"
                    hint = " — bound to all interfaces"

                if sev != "LOW":
                    proc_name = ""
                    if pid:
                        try:
                            proc_name = psutil.Process(pid).name()
                        except Exception:
                            pass

                    findings.append(CanonicalFinding(
                        id=f"NSAT-HOST-{seq:03d}",
                        title=f"Active Listening Socket: {host}:{port}{hint}",
                        category="network_exposure",
                        severity=sev,
                        confidence=1.0,
                        confidence_label="Confirmed by safe check",
                        source=self.scanner_name,
                        asset=f"{host}:{port}",
                        port=port,
                        binding_address=host,
                        description=(
                            f"A socket is actively listening on {host}:{port}"
                            f"{hint}. Process: '{proc_name}' (PID {pid})."
                        ),
                        impact="Externally reachable service exposes attack surface.",
                        recommendation="Verify this service is intentional; bind to 127.0.0.1 if not public-facing.",
                        evidence=[FindingEvidence(
                            type="LIVE_SOCKET",
                            description=f"Active listener on {host}:{port} (PID {pid}, {proc_name})",
                        )],
                    ))
                    seq += 1
        except ImportError:
            pass  # psutil not installed — graceful degradation
        except Exception:
            pass  # Permission denied on some OS configurations — graceful

        return seq, findings

    def _check_malware_indicators(self, target_path: Path, findings: list, seq: int):
        """Scan source files for suspicious hook / spyware library imports."""
        for file_path in target_path.rglob("*"):
            if not file_path.is_file():
                continue
            if any(p in {"node_modules", "vendor", ".venv", "venv", ".git", "dist", "build"} for p in file_path.parts):
                continue
            if file_path.suffix.lower() not in {".py", ".js", ".ts", ".cpp", ".java", ".go", ".rs"}:
                continue

            try:
                content = file_path.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue

            for idx, line in enumerate(content.splitlines(), 1):
                for indicator, description in SUSPICIOUS_HOOK_PATTERNS:
                    if indicator in line:
                        findings.append(CanonicalFinding(
                            id=f"NSAT-HOST-{seq:03d}",
                            title=f"Suspicious Hook / Surveillance Library Detected: {indicator}",
                            category="code_sast",
                            severity="HIGH",
                            confidence=0.85,
                            confidence_label="Detected structurally",
                            source=self.scanner_name,
                            asset=file_path.name,
                            file_path=str(file_path),
                            line_number=idx,
                            description=(
                                f"Library '{indicator}' is referenced in source code. {description}. "
                                "This pattern is associated with keylogging, screen capture, or input surveillance."
                            ),
                            impact="If malicious, enables covert capture of user keystrokes, credentials, or screen content.",
                            recommendation=(
                                f"Audit the intent of '{indicator}' usage. If not intentionally required, remove it. "
                                "Run git blame to identify when it was introduced."
                            ),
                            evidence=[FindingEvidence(
                                type="MALWARE_INDICATOR",
                                description=f"Suspicious import: {indicator}",
                                snippet=line.strip()[:80],
                                line_number=idx,
                            )],
                        ))
                        seq += 1

        return seq, findings
