"""Checagens passivas de postura de segurança.

Todas as funções fazem apenas requisições HTTP padrão (GET/OPTIONS/HEAD)
e inspecionam a resposta. Nenhuma tenta explorar, injetar payloads ou
burlar controles — o objetivo é relatar configuração, não atacar.
"""
import requests

from .utils import INFO, LOW, MEDIUM, HIGH, finding

TIMEOUT = 10
HEADERS = {"User-Agent": "mini-web-scanner/1.0 (portfolio; passive)"}

# Headers de segurança esperados e a severidade da ausência de cada um
SECURITY_HEADERS = {
    "Strict-Transport-Security": (MEDIUM, "Força HTTPS (HSTS)."),
    "Content-Security-Policy": (MEDIUM, "Mitiga XSS e injeção de conteúdo."),
    "X-Frame-Options": (LOW, "Protege contra clickjacking."),
    "X-Content-Type-Options": (LOW, "Impede MIME sniffing."),
    "Referrer-Policy": (INFO, "Controla vazamento de referrer."),
    "Permissions-Policy": (INFO, "Restringe APIs do navegador."),
}


def _get(url):
    return requests.get(url, headers=HEADERS, timeout=TIMEOUT, allow_redirects=True)


def check_reachability(url):
    """Confirma que o alvo responde e reporta status/servidor."""
    try:
        resp = _get(url)
    except requests.RequestException as exc:
        return None, [finding("reachability", HIGH,
                              "Alvo inacessível.", {"erro": str(exc)})]
    server = resp.headers.get("Server", "(não divulgado)")
    return resp, [finding("reachability", INFO,
                          f"Alvo respondeu {resp.status_code}.",
                          {"status": resp.status_code, "server": server})]


def check_security_headers(resp):
    """Lista headers de segurança presentes e ausentes."""
    out = []
    present = {k.lower() for k in resp.headers}
    for header, (sev, why) in SECURITY_HEADERS.items():
        if header.lower() in present:
            out.append(finding("headers", INFO, f"Presente: {header}."))
        else:
            out.append(finding("headers", sev, f"Ausente: {header}.",
                               {"motivo": why}))
    return out


def check_tls(url):
    """Sinaliza se o site serve em HTTP sem redirecionar para HTTPS."""
    if url.startswith("https://"):
        return [finding("tls", INFO, "Servido via HTTPS.")]
    try:
        resp = _get(url)
        if resp.url.startswith("https://"):
            return [finding("tls", INFO, "HTTP redireciona para HTTPS.")]
    except requests.RequestException:
        pass
    return [finding("tls", HIGH, "Servido via HTTP sem redirecionar para HTTPS.")]


def check_http_methods(url):
    """Lê os métodos anunciados em OPTIONS (apenas leitura do header Allow)."""
    try:
        resp = requests.options(url, headers=HEADERS, timeout=TIMEOUT)
    except requests.RequestException as exc:
        return [finding("methods", INFO, "OPTIONS não respondeu.",
                       {"erro": str(exc)})]
    allow = resp.headers.get("Allow")
    if not allow:
        return [finding("methods", INFO, "Servidor não divulgou métodos (Allow).")]
    risky = {m for m in ("PUT", "DELETE", "TRACE", "PATCH")
             if m in allow.upper()}
    sev = LOW if risky else INFO
    msg = f"Métodos anunciados: {allow}."
    if risky:
        msg += f" Revisar exposição de: {', '.join(sorted(risky))}."
    return [finding("methods", sev, msg, {"allow": allow})]


def check_cookies(resp):
    """Verifica flags Secure e HttpOnly nos cookies de sessão."""
    out = []
    for cookie in resp.cookies:
        flags = []
        if not cookie.secure:
            flags.append("sem Secure")
        if not cookie.has_nonstandard_attr("HttpOnly"):
            flags.append("sem HttpOnly")
        if flags:
            out.append(finding("cookies", LOW,
                              f"Cookie '{cookie.name}': {', '.join(flags)}."))
        else:
            out.append(finding("cookies", INFO,
                              f"Cookie '{cookie.name}': flags OK."))
    if not out:
        out.append(finding("cookies", INFO, "Nenhum cookie definido na resposta."))
    return out


def check_robots(url):
    """Checa presença de robots.txt (apenas informativo)."""
    try:
        resp = requests.get(f"{url}/robots.txt", headers=HEADERS, timeout=TIMEOUT)
        if resp.status_code == 200 and resp.text.strip():
            return [finding("robots", INFO, "robots.txt encontrado.",
                           {"linhas": len(resp.text.splitlines())})]
    except requests.RequestException:
        pass
    return [finding("robots", INFO, "robots.txt ausente ou vazio.")]


ALL_CHECKS_REQUIRING_RESP = (check_security_headers, check_cookies)
ALL_CHECKS_REQUIRING_URL = (check_tls, check_http_methods, check_robots)
