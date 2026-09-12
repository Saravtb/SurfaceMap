```
  ____             __                 __  ___
 / __/_ ____ _____/ /__ _______ __  /  |/  /__ ____
_\ \/ // / __/ _ / _ / __/ -_) //  / /|_/ / _ `/ _ \
/___/\_,_/_/  \_,_/_//_/\__/\_,_/ /_/  /_/\_,_/ .__/
                                             /_/
        Attack Surface Mapping for Pentesting
```

Todo pentest comeca do mesmo jeito: um alvo, e um bocado de perguntas sem
resposta. Que subdominios existem? O que esta escutando em cada porta?
Que tecnologia roda por tras daquele HTTP 200? Existe um `.git` exposto
esperando para ser encontrado?

**SurfaceMap** e uma ferramenta de linha de comando que faz essas
perguntas por voce, de forma sistematica, e devolve um mapa da superficie
de ataque — em JSON para automatizar, em HTML e PDF para anexar num
relatorio, em Markdown para colar direto no ticket.

Aponte para um **dominio**, um **IP**, um **bloco CIDR** ou um **range de
enderecos**; o resto e com a ferramenta.

---

### Indice

- [Aviso legal](#aviso-legal)
- [O pipeline de reconhecimento](#o-pipeline-de-reconhecimento)
- [Tipos de alvo suportados](#tipos-de-alvo-suportados)
- [O que ela coleta](#o-que-ela-coleta)
- [Instalacao](#instalacao)
- [Uso](#uso)
- [Opcoes principais](#opcoes-principais)
- [Exemplos](#exemplos)
- [Estrutura do projeto](#estrutura-do-projeto)
- [O que ela nao faz de proposito](#o-que-ela-nao-faz-de-proposito)

---

## Aviso legal

> Esta ferramenta executa varredura ativa de rede: portas, subdominios,
> diretorios web. Isso nao e algo que se aponta para qualquer dominio que
> passar na frente.
>
> **Use apenas contra alvos para os quais voce possui autorizacao
> explicita e por escrito** — um contrato de pentest, um programa de bug
> bounty com escopo definido, ou ativos que voce mesmo administra.
>
> Uso nao autorizado de ferramentas de varredura contra sistemas de
> terceiros pode configurar crime e violar termos de servico. A
> ferramenta pede essa confirmacao antes de rodar; leve a serio, a
> responsabilidade e sempre de quem aperta o Enter.

---

## O pipeline de reconhecimento

```
     alvo: dominio | IP | bloco CIDR | range de IPs
                         |
                         v
        DNS + WHOIS + subdominios  (dominios: CT logs e brute force)
                         |
                         v
        portas abertas  (TCP connect interno, ou nmap com -sV)
                         |
                         v
        fingerprint HTTP/HTTPS  (headers, titulo, tecnologia)
                         |
                         v
        diretorios sensiveis + screenshot de cada host vivo
                         |
                         v
        relatorio consolidado: JSON / Markdown / HTML / PDF
```

Cada etapa pode ser ligada, desligada ou ajustada por flag — o pipeline
inteiro roda por padrao, mas nada aqui e tudo-ou-nada.

---

## Tipos de alvo suportados

| Alvo | Exemplo | O que roda |
|---|---|---|
| Dominio | `exemplo.com.br` | DNS, WHOIS, enumeracao de subdominios, e o restante do pipeline para cada host resolvido |
| IP unico | `192.168.1.10` | WHOIS do IP, e o restante do pipeline |
| Bloco CIDR | `192.168.1.0/24` | Expande para os IPs do bloco (host bits; `/31` e `/32` incluem ambos os enderecos), WHOIS do primeiro IP como amostra, e o restante do pipeline para cada IP |
| Range de IPs | `192.168.1.10-192.168.1.20` ou `192.168.1.10-20` (abreviado, ultimo octeto) | Mesmo tratamento de um bloco CIDR |

Para alvos IP/CIDR/range a ferramenta tambem tenta resolver o **PTR**
(DNS reverso) de cada endereco (desative com `--no-ptr`), e a descoberta
de diretorios roda em todos os IPs com HTTP ativo por padrao — nao so no
"alvo principal", conceito que so existe para dominios.

> Um bloco grande (uma `/16`, por exemplo) pode ter dezenas de milhares
> de enderecos. A ferramenta so escaneia em profundidade ate `--max-hosts`
> deles (padrao 15) e avisa quando a lista foi truncada. Aumente
> `--max-hosts` conforme o escopo autorizado do teste — nunca alem dele.

---

## O que ela coleta

| Modulo | Descricao |
|---|---|
| DNS | Registros A, AAAA, MX, NS, TXT, SOA, CNAME + teste de zone transfer (AXFR) — apenas para alvos de dominio |
| WHOIS | Dados de registro do dominio, ou do IP/bloco quando o alvo e uma rede |
| Subdominios | Enumeracao passiva via Certificate Transparency (crt.sh) + brute force ativo por wordlist — apenas para alvos de dominio |
| Portas | Varredura TCP connect nas portas mais comuns (ou range customizado); opcionalmente via `nmap` com deteccao de servico/versao (`--use-nmap`) |
| HTTP/HTTPS | Status, headers, titulo da pagina e fingerprint leve de tecnologias (WordPress, Nginx, Laravel, etc.) |
| Diretorios | Descoberta de caminhos/arquivos sensiveis comuns (`.git`, `.env`, painel admin, backups, etc.) |
| Screenshots | Captura de tela de cada host web ativo, via Chromium headless (`--screenshots`, opcional) |

O resultado agregado e exportado em **JSON** (para automatizar),
**Markdown** (para colar num ticket), **HTML** (relatorio navegavel, tema
escuro, com tabelas por host e screenshots incorporados) e,
opcionalmente, **PDF** (`--pdf`) — o mesmo HTML renderizado por um
Chromium headless, pronto para anexar num relatorio de pentest ou
mandar por email.

---

## Instalacao

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

`dnspython` e opcional mas recomendado: sem ele, a coleta de DNS fica
limitada a registros A e o teste de AXFR e pulado.

Para usar `--screenshots` ou `--pdf` tambem e preciso instalar o
Playwright e um navegador Chromium (nao vem no `requirements.txt` por
padrao, ja que baixa cerca de 150MB):

```bash
pip install playwright
playwright install chromium
```

Sem isso, as duas flags apenas imprimem um aviso e a ferramenta continua
normalmente — nenhuma outra etapa depende do Playwright.

---

## Uso

```bash
python main.py exemplo.com.br
```

Voce sera solicitado a confirmar autorizacao interativamente. Para rodar
sem prompt (em CI, por exemplo, com autorizacao ja documentada):

```bash
python main.py exemplo.com.br --yes
```

### Opcoes principais

```
positional:
  target                     Dominio, IP unico, bloco CIDR ou range de IPs (ex: exemplo.com.br,
                              192.168.1.10, 192.168.1.0/24, 192.168.1.10-192.168.1.20)

  -o, --output DIR           Diretorio de saida (padrao: reports/<alvo>-<timestamp>)
  -t, --threads N            Threads para brute force/scan (padrao: 30)
  --ports RANGE              Ex: "1-1024" ou "22,80,443" (padrao: top ports internas)
  --max-hosts N              Maximo de hosts analisados em profundidade: subdominios extras
                              (dominio) ou enderecos IP (CIDR/range) (padrao: 15)
  --no-ptr                   Nao resolver PTR (DNS reverso) para alvos IP/CIDR/range
  --use-nmap                 Usa o nmap (se instalado) para escanear portas com deteccao de
                              servico/versao, em vez do scanner TCP connect interno. Se o
                              nmap nao estiver no PATH ou a execucao falhar, cai automaticamente
                              para o scanner interno.
  --nmap-args ARGS            Argumentos extras passados ao nmap (padrao: "-sV")
  --nmap-timeout N            Timeout em segundos por host para o nmap (padrao: 300)
  --subdomain-wordlist PATH  Wordlist customizada para brute force de subdominios
  --dir-wordlist PATH        Wordlist customizada para descoberta de diretorios
  --dir-enum-all             Roda descoberta de diretorios em todos os hosts, nao so no alvo principal
  --screenshots              Captura screenshot de cada host web ativo (requer Playwright + Chromium)
  --screenshot-timeout MS    Timeout em ms para carregar a pagina antes do screenshot (padrao: 15000)
  --pdf                      Exporta o relatorio tambem em PDF (requer Playwright + Chromium)

  --skip-dns                 Pula coleta de registros DNS
  --skip-zone-transfer       Pula teste de AXFR
  --skip-whois               Pula consulta WHOIS
  --skip-subdomains          Pula enumeracao de subdominios
  --no-passive-subdomains    Desativa apenas a fonte passiva (crt.sh)
  --no-active-subdomains     Desativa apenas o brute force ativo
  --skip-ports               Pula varredura de portas
  --skip-http                Pula fingerprint HTTP/HTTPS
  --skip-dirs                Pula descoberta de diretorios

  -y, --yes                  Confirma autorizacao sem prompt interativo
```

---

## Exemplos

Reconhecimento completo, portas customizadas, saida em pasta especifica:

```bash
python main.py exemplo.com.br --ports 1-1024 -o relatorios/exemplo --yes
```

Varredura de portas usando nmap com deteccao de servico e scripts padrao
(requer `nmap` instalado no sistema; sem privilegio de root o nmap usa
automaticamente TCP connect scan em vez de SYN scan):

```bash
python main.py exemplo.com.br --use-nmap --nmap-args "-sV -sC" --yes
```

Reconhecimento com captura de screenshot de cada host web encontrado:

```bash
python main.py exemplo.com.br --screenshots --yes
```

Relatorio completo com screenshots e exportacao em PDF, pronto para
anexar num documento de pentest:

```bash
python main.py exemplo.com.br --screenshots --pdf --yes
```

Somente reconhecimento passivo — sem tocar diretamente no alvo com scans
ativos de porta ou diretorio, apenas DNS, WHOIS e subdominios via CT logs:

```bash
python main.py exemplo.com.br --skip-ports --skip-dirs --no-active-subdomains --yes
```

Varredura de um bloco CIDR (a rede interna de um cliente, por exemplo),
elevando o limite de hosts para cobrir toda a `/24`:

```bash
python main.py 192.168.1.0/24 --max-hosts 254 --yes
```

Varredura de um range especifico de IPs, com a sintaxe abreviada de
ultimo octeto:

```bash
python main.py 10.0.0.100-150 --yes
```

---

## Estrutura do projeto

```
surfacemap/
  cli.py                 Orquestracao / argparse
  utils.py                Helpers (validacao de dominio, banner, aviso legal)
  modules/
    dns_recon.py          Registros DNS + AXFR
    subdomains.py          crt.sh (passivo) + brute force (ativo)
    ports.py                Varredura de portas TCP (scanner interno)
    nmap_scan.py             Backend opcional de varredura via nmap (-sV, XML parsing)
    http_probe.py           Fingerprint HTTP/HTTPS
    dir_enum.py              Descoberta de diretorios/arquivos
    whois_lookup.py          WHOIS
    screenshot.py            Captura de tela opcional via Playwright/Chromium
  report/
    builder.py               Geracao de JSON/Markdown/HTML
    pdf.py                    Exportacao opcional em PDF via Playwright/Chromium
  wordlists/
    subdomains.txt
    common-dirs.txt
main.py                Ponto de entrada (python main.py <alvo>)
```

---

## O que ela nao faz de proposito

Nenhuma ferramenta de reconhecimento e onisciente, e esta aqui prefere
ser honesta sobre isso a fingir cobertura total:

- Por padrao a varredura de portas usa TCP connect scan simples (sem SYN
  scan), o que e mais lento que o `nmap` mas nao requer privilegios de
  root. Use `--use-nmap` para deteccao de servico/versao via `nmap`
  quando ele estiver instalado — a ferramenta cai de volta para o
  scanner interno automaticamente se o binario nao existir ou a execucao
  falhar.
- `--screenshots` e `--pdf` exigem `pip install playwright` + `playwright
  install chromium` (ou um Chromium ja instalado e compativel com a
  versao do pacote `playwright`); sem isso, cada flag e ignorada com um
  aviso e o restante do reconhecimento/relatorio roda normalmente.
- A enumeracao de subdominios ativa depende da wordlist fornecida; para
  cobertura maior, use uma wordlist maior (ex. SecLists) via
  `--subdomain-wordlist`.
- O fingerprint de tecnologias e heuristico (regex sobre headers/HTML) e
  pode gerar falsos positivos ou negativos.
- Esta ferramenta nao substitui uma analise manual aprofundada nem
  testes de exploracao; ela existe para acelerar a fase de
  reconhecimento, nao para substituir quem interpreta os resultados.
