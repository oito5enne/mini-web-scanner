# Mini Web Scanner — Análise Passiva de Postura de Segurança

Ferramenta de linha de comando em Python que avalia a **configuração de segurança** de uma aplicação web e gera um relatório priorizado por severidade. É **passiva**: faz apenas requisições HTTP padrão e inspeciona as respostas — não injeta payloads, não tenta explorar falhas nem burlar controles.

## ⚠️ Uso ético

Escaneie **somente**:
- sistemas que você possui;
- sistemas para os quais tem **autorização por escrito**;
- alvos de treino propositais — [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/), [DVWA](https://github.com/digininja/DVWA), `testphp.vulnweb.com`.

Escanear sistemas de terceiros sem permissão pode ser crime. A ferramenta exige a flag `--i-have-authorization` justamente para tornar esse compromisso explícito.

## O que ele verifica

| Check | O que avalia |
|---|---|
| **Reachability** | Alvo responde? Status HTTP e banner do servidor |
| **TLS** | Serve em HTTPS? HTTP redireciona para HTTPS? |
| **Security headers** | HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy |
| **HTTP methods** | Métodos anunciados em `OPTIONS` (sinaliza PUT/DELETE/TRACE/PATCH) |
| **Cookies** | Flags `Secure` e `HttpOnly` nos cookies definidos |
| **robots.txt** | Presença e tamanho (informativo) |

Cada achado recebe severidade **HIGH / MEDIUM / LOW / INFO**, e o relatório vem ordenado do mais crítico ao informativo.

## Como rodar

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt

# Alvo de treino público, com autorização confirmada
python scanner.py testphp.vulnweb.com --i-have-authorization

# Salvando o relatório em JSON
python scanner.py testphp.vulnweb.com --i-have-authorization --json relatorio.json
```

Exemplo de saída em `examples/sample_report.json`.

## Estrutura

```
mini-web-scanner/
├── scanner.py           # CLI + orquestração + gate de autorização
├── scanner/
│   ├── checks.py        # cada verificação, isolada e testável
│   ├── report.py        # saída console (colorida) e JSON
│   └── utils.py         # severidades e normalização de URL
└── examples/
    └── sample_report.json
```

Arquitetura modular: cada check é uma função independente, fácil de estender — adicionar uma nova verificação é escrever uma função e registrá-la na lista.

## Stack

Python · Requests · argparse

## Próximos passos (roadmap)

- [ ] Exportar relatório em HTML
- [ ] Checagem de versões conhecidas no banner do servidor
- [ ] Modo de concorrência para varrer vários alvos
