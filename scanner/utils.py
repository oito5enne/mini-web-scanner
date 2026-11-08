"""Utilidades compartilhadas: níveis de severidade e normalização de URL."""
from urllib.parse import urlparse

# Níveis usados na classificação de cada achado
INFO = "INFO"
LOW = "LOW"
MEDIUM = "MEDIUM"
HIGH = "HIGH"

SEVERITY_ORDER = {HIGH: 0, MEDIUM: 1, LOW: 2, INFO: 3}


def normalize_url(raw):
    """Garante esquema e remove barra final. Lança ValueError se inválida."""
    raw = raw.strip()
    if not raw.startswith(("http://", "https://")):
        raw = "https://" + raw
    parsed = urlparse(raw)
    if not parsed.netloc:
        raise ValueError(f"URL inválida: {raw!r}")
    return f"{parsed.scheme}://{parsed.netloc}"


def finding(check, severity, message, detail=None):
    """Monta um achado padronizado (dicionário serializável)."""
    return {
        "check": check,
        "severity": severity,
        "message": message,
        "detail": detail or {},
    }
