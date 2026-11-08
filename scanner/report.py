"""Formatação de relatório: console legível e JSON serializável."""
import json

from .utils import SEVERITY_ORDER, HIGH, MEDIUM, LOW, INFO

# Cores ANSI por severidade (degradam para texto puro se o terminal não suportar)
COLORS = {HIGH: "\033[91m", MEDIUM: "\033[93m", LOW: "\033[94m", INFO: "\033[90m"}
RESET = "\033[0m"


def sort_findings(findings):
    return sorted(findings, key=lambda f: SEVERITY_ORDER[f["severity"]])


def to_console(target, findings, use_color=True):
    lines = [f"\nRelatório de postura de segurança — {target}", "=" * 56]
    counts = {HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0}
    for f in sort_findings(findings):
        counts[f["severity"]] += 1
        tag = f["severity"]
        if use_color:
            tag = f"{COLORS[f['severity']]}{tag:<6}{RESET}"
        else:
            tag = f"{tag:<6}"
        lines.append(f"[{tag}] {f['message']}")
    summary = "  ".join(f"{k}: {counts[k]}" for k in (HIGH, MEDIUM, LOW, INFO))
    lines.append("-" * 56)
    lines.append(f"Resumo  {summary}")
    return "\n".join(lines)


def to_json(target, findings):
    return json.dumps(
        {"target": target, "findings": sort_findings(findings)},
        indent=2, ensure_ascii=False,
    )
