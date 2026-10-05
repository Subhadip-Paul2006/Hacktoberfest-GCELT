"""Code relevance and noise reduction filter for NSAT."""

from pathlib import Path
import re
from typing import Tuple


NON_SOURCE_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".bmp", ".webp",
    ".mp4", ".mp3", ".wav", ".avi", ".mov",
    ".pdf", ".zip", ".tar", ".gz", ".7z", ".rar",
    ".exe", ".dll", ".so", ".dylib", ".bin", ".o", ".a",
    ".ttf", ".woff", ".woff2", ".eot",
    ".pyc", ".class",
    ".md", ".markdown", ".rst", ".txt", ".csv", ".tsv",
}

VENDOR_DIR_PARTS = {
    "node_modules", "vendor", ".venv", "venv", "env", "packages",
    "site-packages", "dist", "build", "target", "out", ".git",
    "egg-info", "nsat.egg-info",
}

# Regex to detect security-sensitive constructs in raw text regardless of identifier names
SECURITY_SENSITIVE_HINTS = re.compile(
    r"(?i)\b(subprocess|os\.system|popen|exec|eval|socket|bind|listen|cursor\.execute|"
    r"SELECT\b|INSERT\b|UPDATE\b|DELETE\b|HttpServletRequest|SpringApplication|"
    r"FastAPI|Flask|Express|require\(['\"]child_process['\"]|dangerouslySetInnerHTML|"
    r"jwt|password|secret|token|hash|md5|sha1|auth|cipher|crypto|INADDR_ANY)\b"
)

TRIVIAL_PRINT_HINTS = re.compile(
    r"""(?xi)
    ^\s*(
        print\s*\(\s*["']hello\s*world!?["']\s*\) |
        System\.out\.println\s*\(\s*["']hello\s*world!?["']\s*\)\s*;? |
        std::cout\s*<<\s*["']hello\s*world!?["']\s*(<<\s*std::endl)?\s*;? |
        console\.log\s*\(\s*["']hello\s*world!?["']\s*\)\s*;?
    )\s*$
    """
)


class RelevanceFilter:
    """Evaluates whether a discovered file is relevant for security analysis."""

    @staticmethod
    def assess_path(file_path: Path, root_path: Path) -> Tuple[bool, str]:
        """
        Assess path-based relevance before reading file content.
        Returns: (is_relevant, reason)
        """
        # 1. Binary or media extension
        suffix = file_path.suffix.lower()
        if suffix in NON_SOURCE_EXTENSIONS:
            return False, "binary_or_asset"

        # 2. Check path segments against vendor directories
        try:
            rel_parts = file_path.relative_to(root_path).parts
        except ValueError:
            rel_parts = file_path.parts

        for part in rel_parts[:-1]:
            if part in VENDOR_DIR_PARTS or part.startswith("."):
                return False, f"vendor_or_ignored_dir:{part}"

        return True, "valid_candidate"

    @staticmethod
    def assess_content(file_path: Path, content: str) -> Tuple[bool, str]:
        """
        Assess content-based relevance.
        Ensures trivial hello-world code is deprioritized without suppressing
        code merely because variable or function names are meaningless.
        """
        stripped = content.strip()
        if not stripped:
            return False, "empty_file"

        # If any security-sensitive structural indicator is present, ALWAYS keep it
        # regardless of how short the file is or how meaningless the identifiers are!
        if SECURITY_SENSITIVE_HINTS.search(content):
            return True, "security_relevant_structure"

        lines = [line.strip() for line in stripped.splitlines() if line.strip() and not line.strip().startswith(("#", "//", "/*", "*"))]
        
        # Check for trivial Hello World single-statement files
        if len(lines) <= 3:
            for line in lines:
                if TRIVIAL_PRINT_HINTS.match(line):
                    return False, "trivial_hello_world"

        return True, "source_code"
