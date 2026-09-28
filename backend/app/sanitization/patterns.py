"""
Compiled regex patterns used by the sanitization pipeline.

All patterns are pre-compiled at import time for performance.
None of these patterns execute any matched content — they are
purely for detection and substitution of sensitive strings.
"""
import re

# ── Secret / credential patterns ─────────────────────────────────────────────

# AWS access key IDs (20-char uppercase alphanumeric starting with AKIA / ASIA / AROA)
AWS_ACCESS_KEY = re.compile(r"\b(AKIA|ASIA|AROA|AIPA|ANPA|ANVA|APKA)[A-Z0-9]{16}\b")

# AWS secret access key (40-char base64-ish after common assignment operators)
AWS_SECRET_KEY = re.compile(
    r"(?i)(?:aws[_\-\s]?secret[_\-\s]?(?:access[_\-\s]?)?key|aws_secret)\s*[=:]\s*['\"]?([A-Za-z0-9/+]{40})['\"]?"
)

# Generic API-key assignment patterns (key=VALUE or key: VALUE)
GENERIC_API_KEY = re.compile(
    r"(?i)(?:api[_\-]?key|apikey|token|secret|password|passwd|pwd)\s*[=:]\s*['\"]?([A-Za-z0-9_\-\.]{20,})['\"]?",
    re.MULTILINE,
)

# Authorization / Bearer header  (Authorization: Bearer <token>)
# Captures the token value after the Bearer keyword
BEARER_TOKEN = re.compile(
    r"(?i)(?:authorization|bearer)\s*[=:\s]\s*['\"]?([A-Za-z0-9_\-\.]{20,})['\"]?",
    re.MULTILINE,
)

# PEM private key headers/footers
PRIVATE_KEY_HEADER = re.compile(
    r"-----BEGIN\s+(?:RSA\s+|EC\s+|DSA\s+|OPENSSH\s+|ENCRYPTED\s+)?PRIVATE KEY-----",
    re.IGNORECASE,
)
PRIVATE_KEY_FOOTER = re.compile(
    r"-----END\s+(?:RSA\s+|EC\s+|DSA\s+|OPENSSH\s+|ENCRYPTED\s+)?PRIVATE KEY-----",
    re.IGNORECASE,
)

# PEM certificate / public key blocks (less critical, still flag for hygiene)
PEM_BLOCK = re.compile(
    r"-----BEGIN\s+(?:CERTIFICATE|PUBLIC KEY|CERTIFICATE REQUEST)-----.*?-----END\s+(?:CERTIFICATE|PUBLIC KEY|CERTIFICATE REQUEST)-----",
    re.DOTALL | re.IGNORECASE,
)

# Email addresses (only redacted when redact_pii=True)
EMAIL = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")

# ── Shell / script patterns (flagged as suspicious; content kept inert) ───────

SHELL_PATTERNS: list[tuple[str, re.Pattern]] = [
    # Command substitution
    ("shell_substitution",  re.compile(r"\$\([^)]*\)|`[^`]*`")),
    # Pipe chains / redirections in a shell context
    ("shell_redirect",      re.compile(r"(?:^|\s)(rm\s+-[rf]{1,2}|wget\s|curl\s|chmod\s+[0-7]{3,4}|sudo\s|bash\s+-c|sh\s+-c|nc\s+|netcat\s)", re.IGNORECASE | re.MULTILINE)),
    # Common dangerous shell meta-characters in sequence
    ("shell_metachar",      re.compile(r"(?:;\s*(?:bash|sh|cmd|powershell|python|perl|ruby|php)\b|&&\s*(?:bash|sh|wget|curl)\b)", re.IGNORECASE)),
    # Script injection patterns
    ("script_eval",         re.compile(r"\beval\s*\(|\bexec\s*\(|\bexecfile\s*\(|\bcompile\s*\(", re.IGNORECASE)),
    # HTML/JS injection
    ("xss_script_tag",      re.compile(r"<script[\s>]|</script>|javascript\s*:", re.IGNORECASE)),
    # SQL injection signatures
    ("sql_injection",       re.compile(r"(?i)(?:'\s*(?:OR|AND)\s*'?\d|UNION\s+(?:ALL\s+)?SELECT|DROP\s+TABLE|INSERT\s+INTO|DELETE\s+FROM\s+\w|--\s*$)", re.MULTILINE)),
    # OS-level module access (Python-like)
    ("os_module_access",    re.compile(r"\b(?:import\s+os|import\s+subprocess|os\.system\s*\(|subprocess\.(?:run|call|Popen|check_output)\s*\()", re.IGNORECASE)),
    # Path traversal
    ("path_traversal",      re.compile(r"(?:\.\.[\\/]){2,}")),
]

# ── Control character pattern ─────────────────────────────────────────────────

# Strip all C0/C1 control chars EXCEPT tab (\x09), LF (\x0A), CR (\x0D)
CONTROL_CHARS = re.compile(r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F\x80-\x9F]")

# Multiple consecutive blank lines → single blank line
EXCESS_BLANK_LINES = re.compile(r"\n{3,}")

# Leading/trailing whitespace on each line
LINE_TRAILING_WS = re.compile(r"[ \t]+$", re.MULTILINE)
