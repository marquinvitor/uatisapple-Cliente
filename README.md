# UatisApple - Cliente 🔐📱

Cliente de mensageria segura com **Criptografia de Ponta a Ponta (E2EE - End-to-End Encryption)**, desenvolvido em Python. O sistema implementa uma camada criptográfica robusta para garantir confidencialidade, autenticidade, integridade e resistência a ataques comuns de rede, como **Man-in-the-Middle (MitM)**, **Adulteração de Mensagens (Tampering)** e **Ataques de Replay**.

---

## 📋 Índice

- [Visão Geral](#-visão-geral)
- [Arquitetura Criptográfica e Protocolo](#-arquitetura-criptográfica-e-protocolo)
- [Estrutura do Projeto](#-estrutura-do-projeto)
- [Pré-requisitos](#-pré-requisitos)
- [Instalação e Configuração](#-instalação-e-configuração)
- [Configuração de Certificados (`certs/`)](#-configuração-de-certificados-certs)
- [Como Executar](#-como-executar)
- [Testes de Segurança Embutidos](#-testes-de-segurança-embutidos)

---

## 📖 Visão Geral

O **UatisApple-Cliente** estabelece uma conexão TCP estruturada com o servidor de mensagens, realiza a autenticação do servidor utilizando **Certificate Pinning** e assinaturas digitais **RSA-PSS**, efetua uma troca de chaves Diffie-Hellman em curva elíptica (**X25519**) com derivação via **HKDF-SHA256**, e cifra as comunicações ponta a ponta com **AES-128-GCM**.

### Principais Garantias de Segurança
- **Confidencialidade:** Mensagens cifradas com AES-128-GCM; apenas os destinatários possuem as chaves de decifragem.
- **Autenticidade e Integridade (AEAD):** Validação de autenticidade através das tags de 16 bytes do GCM e metadados associados (AAD).
- **Proteção Anti-MitM:** Verificação estrita de *Certificate Pinning* e validação de assinatura RSA-PSS do servidor sobre os parâmetros da sessão.
- **Proteção Anti-Replay:** Monotonicidade estrita no número de sequência de cada mensagem (`seq_no`).
- **PFS (Perfect Forward Secrecy):** Uso de chaves efêmeras X25519 geradas dinamicamente a cada sessão.

---

## 🛡️ Arquitetura Criptográfica e Protocolo

O fluxo de comunicação segue uma série de requisitos criptográficos bem definidos:

### 1. Framing TCP Baseado em Comprimento
Toda mensagem trocada na conexão TCP possui um cabeçalho de 4 bytes (*big-endian*) informando o tamanho total do payload. Isso evita problemas de fragmentação de pacotes na rede (`src/network.py`).

### 2. Fluxo do Handshake
```
Cliente                                               Servidor
   |                                                     |
   | --- [0x01] CLIENT_HELLO (UUID, pk_client) --------> |
   |                                                     |
   | <-- [0x02] SERVER_HELLO (pk_srv, salt, sig, cert) - |
   |                                                     |
   | [Valida Certificate Pinning (server.crt)]           |
   | [Valida Assinatura RSA-PSS com SHA256]              |
   |                                                     |
```

1. **RC01 - Chaves Efêmeras:** O cliente gera um par de chaves X25519 efêmeras locais (`priv_client`, `pk_client`).
2. **RC02 - CLIENT_HELLO (0x01):** O cliente conecta ao servidor via TCP e envia seu identificador único (UUID v4 em 16 bytes) e sua chave pública de 32 bytes.
3. **RC03 - SERVER_HELLO (0x02) & Autenticação:**
   - O servidor responde com: chave pública efêmera do servidor (`pk_server`), `salt_srv` (16 bytes), assinatura digital RSA-PSS e certificado digital X.509.
   - **Certificate Pinning:** O cliente confere byte a byte o certificado recebido com a cópia local pinada (`certs/server.crt`).
   - **Assinatura RSA-PSS:** O cliente reconstrói o digest $H = \text{SHA256}(\text{pk\_server} \parallel \text{pk\_client} \parallel \text{client\_id} \parallel \text{salt})$ e verifica a assinatura RSA-PSS com padding MGF1(SHA256).

### 3. Derivação de Chaves de Sessão (RC04)
- **ECDH:** O segredo compartilhado $Z_{AB}$ é computado utilizando a chave privada do cliente e a chave pública efêmera do peer destinatário.
- **HKDF-SHA256:** A partir de $Z_{AB}$ e do `salt_srv`, são derivadas duas chaves simétricas de 128 bits:
  - `key_A2B` (info `b"A2B"`): Chave para envio (Cliente $\to$ Peer).
  - `key_B2A` (info `b"B2A"`): Chave para recepção (Peer $\to$ Cliente).

### 4. Cifragem e Decifragem E2E com AES-128-GCM (RC05 - RC08)
- **Nonce (12 bytes):** Composto por `IV_base_send` (4 bytes aleatórios) + `seq_no` (8 bytes uint64 big-endian).
- **AAD (Dados Autenticados Adicionais - 40 bytes):**
  $$\text{AAD} = \text{sender\_id (16B)} \parallel \text{recipient\_id (16B)} \parallel \text{seq\_no (8B)}$$
  O AAD garante que remetente, destinatário e o número de sequência não possam ser alterados em trânsito sem invalidar o pacote.
- **Formato do Frame E2E:**
  ```
  +--------------+-------------+------------------+--------------------+---------------+---------------------+
  | Tipo (1B)    | Nonce (12B) | sender_id (16B)  | recipient_id (16B) | seq_no (8B)   | Ciphertext + Tag    |
  | 0x10         | (IV + seq)  | (UUID)           | (UUID)             | (uint64)      | (N bytes + 16B tag) |
  +--------------+-------------+------------------+--------------------+---------------+---------------------+
  ```
- **Anti-Replay:** Ao receber uma mensagem, o cliente verifica se `seq_no > seq_recv_atual`. Mensagens duplicadas ou antigas são sumariamente rejeitadas.
- **Anti-Tampering:** Caso um único bit do payload ou do cabeçalho seja adulterado, a verificação da tag GCM falha e gera uma exceção imediata.

---

## 📁 Estrutura do Projeto

```
uatisapple-Cliente/
│
├── certs/                      # Diretório de certificados locais
│   └── .gitkeep                # Mantém o diretório no repositório (server.crt ignorado)
│
├── src/                        # Módulos principais do cliente
│   ├── crypto.py               # Operações criptográficas (X25519, HKDF, AES-GCM, RSA-PSS)
│   └── network.py              # Framing TCP de rede (envio/recebimento com tamanho)
│
├── main.py                     # Ponto de entrada: handshake, sessão E2E e testes de segurança
├── pyproject.toml              # Metadados e dependências do projeto
├── .gitignore                  # Ignora certificados (.crt), caches e venv
└── README.md                   # Documentação do sistema
```

---

## 💻 Pré-requisitos

- **Python:** Versão `>= 3.12` (compatível com `Python 3.14`).
- **Gerenciador de Pacotes:** `uv` (recomendado) ou `pip`/`venv`.
- **Dependência Criptográfica:** [`cryptography`](https://cryptography.io/) versão `>= 50.0.2`.

---

## 🚀 Instalação e Configuração

### 1. Clonar o Repositório
```bash
git clone https://github.com/marquinvitor/uatisapple-Cliente.git
cd uatisapple-Cliente
```

### 2. Configurar o Ambiente

#### Opção A: Utilizando `uv` (Recomendado)
Se você possui o [uv](https://docs.astral.sh/uv/) instalado:
```bash
uv sync
```

#### Opção B: Utilizando `python` padrão (`venv` + `pip`)
```bash
# Criação do ambiente virtual
python3 -m venv .venv

# Ativação do ambiente
# No Linux/macOS:
source .venv/bin/activate
# No Windows:
# .venv\Scripts\activate

# Instalação das dependências
pip install "cryptography>=50.0.2"
```

---

## 🔑 Configuração de Certificados (`certs/`)

Por motivos de segurança e boas práticas, **certificados e chaves privadas não são enviados ao GitHub**. O repositório mantém apenas a estrutura da pasta através do arquivo `.gitkeep`.

Para que o cliente consiga autenticar o servidor via **Certificate Pinning**:
1. Obtenha o certificado do servidor (`server.crt`) em formato **PEM** ou **DER**.
2. Salve o arquivo no diretório `certs/` com o nome exato:
   ```
   certs/server.crt
   ```
3. O `.gitignore` do projeto já está configurado para **ignorar** qualquer arquivo `.crt`, `.pem` ou `.key` dentro da pasta `certs/`, evitando que credenciais locais vazem acidentalmente.

---

## 🏃 Como Executar

1. Certifique-se de que o **Servidor UatisApple** esteja em execução (por padrão em `127.0.0.1:6767`).
2. Se necessário, ajuste as variáveis de rede no início de `main.py`:
   ```python
   HOST = "127.0.0.1"
   PORT = 6767
   CERT_PINADO_PATH = "certs/server.crt"
   ```
3. Execute o cliente:

Com `uv`:
```bash
uv run main.py
```

Ou com `python`:
```bash
python3 main.py
```

### Exemplo de Saída Esperada
```text
[*] Iniciando cliente com ID (UUID v4): a1b2c3d4-e5f6-7890-abcd-ef1234567890
[+] RC01: Chaves efêmeras X25519 geradas localmente.
[+] RC02: Conectado ao servidor em 127.0.0.1:6767
[+] RC02: Frame CLIENT_HELLO enviado com sucesso.
[+] Assinatura RSA-PSS do servidor verificada com sucesso!
[+] RC03: Servidor autenticado com sucesso via RSA-PSS e Pinning!
[+] RC04: Segredo Z_AB calculado e chaves simetricas E2E derivadas com sucesso via HKDF!
[+] RC04: Chaves E2E derivadas com sucesso via HKDF-SHA256!
[+] RC05: Mensagem cifrada com AES-128-GCM e frame E2E gerado (105 bytes).
[*] Simulando recepção do frame pelo destinatário...
[+] RC06/RC07/RC08: Mensagem decifrada com sucesso: 'Mensagem secreta validada ponta a ponta!'

[*] Executando teste obrigatório: Adulteração de payload (Bitflip)...
[+] SUCESSO NO TESTE DE TAMPERING: [-] REJECTED: Falha na Tag GCM! Mensagem adulterada ou corrompida na rede (Anti-Tampering).

[*] Executando teste obrigatório: Ataque Replay (Reenvio do mesmo seq_no)...
[+] SUCESSO NO TESTE DE REPLAY: [-] REJECTED: Ataque Replay detectado! seq_no 1 menor ou igual ao último visto (1).
```

---

## 🧪 Testes de Segurança Embutidos

O script `main.py` inclui simulações automáticas de ataques de rede para comprovar as defesas implementadas:

1. **Teste de Adulteração (Bitflip / Tampering):**
   - O cliente altera intencionalmente o último byte da Tag de autenticação GCM do frame.
   - O decifrador rejeita imediatamente o pacote ao detectar a incoerência criptográfica.
2. **Teste de Replay Attack:**
   - O mesmo frame válido é submetido uma segunda vez ao decifrador com o mesmo `seq_no`.
   - O mecanismo de sequência detecta que `seq_no <= seq_recv_atual` e rejeita a mensagem imediatamente.
