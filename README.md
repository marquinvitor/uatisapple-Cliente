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
======================================================================
       UATISAPPLE: TESTE INTEGRADO E2E COM DOIS CLIENTES E SEGURANÇA       
======================================================================
[+] Servidor Relay já está em execução em 127.0.0.1:6767.

======================================================================
ETAPA 1: Conexão e Handshake com Dois Clientes Reais (Alice e Bob)
======================================================================
[*] [Alice] Conectando ao servidor em 127.0.0.1:6767...
[+] [Alice] CLIENT_HELLO enviado com sucesso.
[+] Assinatura RSA-PSS do servidor verificada com sucesso!
[+] [Alice] Servidor autenticado via Certificate Pinning e RSA-PSS!
[+] [Alice] Sessão registrada no servidor com sucesso.
[*] [Bob] Conectando ao servidor em 127.0.0.1:6767...
[+] [Bob] CLIENT_HELLO enviado com sucesso.
[+] Assinatura RSA-PSS do servidor verificada com sucesso!
[+] [Bob] Servidor autenticado via Certificate Pinning e RSA-PSS!
[+] [Bob] Sessão registrada no servidor com sucesso.
[+] [Bob] Peer configurado! Chaves E2E derivadas com pair_salt.
[+] [Alice] Peer configurado! Chaves E2E derivadas com pair_salt.

======================================================================
ETAPA 2: Troca de Mensagens E2E com Sucesso (Alice <-> Bob)
======================================================================
[*] [Alice] Enviando mensagem E2E para Bob...
[+] [Bob] SUCESSO! Mensagem decifrada: 'Ola Bob! Mensagem ultrassecreta cifrada com AES-128-GCM.'
[*] [Bob] Enviando resposta E2E para Alice...
[+] [Alice] SUCESSO! Resposta decifrada: 'Ola Alice! Mensagem recebida e decifrada perfeitamente de ponta a ponta.'

======================================================================
ETAPA 3: Teste de Integridade - Adulteração de Mensagem (Bitflip no Tráfego)
======================================================================
[*] [Atacante] Bitflip realizado no último byte da Tag de autenticação GCM.
[*] [Alice] Injetando frame adulterado na rede em direção ao relay...
[*] [Bob] Recebendo frame adulterado da rede e tentando decifrar...
[+] SUCESSO NO TESTE ANTI-TAMPERING: Destinatário rejeitou mensagem adulterada!
    Detalhe: [-] REJECTED: Falha na Tag GCM! Mensagem adulterada ou corrompida no tráfego (Anti-Tampering).

======================================================================
ETAPA 4: Teste de Ataque Replay - Envio de Frame com seq_no já Usado
======================================================================
[*] Tentando retransmitir frame anterior que possuía seq_no já utilizado...
[+] SUCESSO NO TESTE DE REPLAY (Servidor): Relay rejeitou replay com código ERROR 5 (REPLAY=0x05)!
[+] SUCESSO NO TESTE DE REPLAY (Destinatário): Destinatário rejeitou seq_no repetido!
    Detalhe: [-] REJECTED: Ataque Replay detectado! seq_no 1 menor ou igual ao último visto (1).

======================================================================
ETAPA 5: Teste de Framing Inválido (Tamanho Incorreto) e Desconexão Segura
======================================================================
[*] Limite max_client_frame_size configurado: 4168 bytes.
[*] [Subteste 5.1] Conectando novo cliente e enviando frame com tamanho anunciado = 0...
[+] [Servidor] Conexão encerrada pelo servidor imediatamente após framing tamanho 0!
[+] [Cliente] Desconexão segura executada no socket de teste 5.1.
[*] [Subteste 5.2] Enviando framing que excede o limite máximo (4668 > 4168)...
[+] [Servidor] Conexão encerrada pelo servidor devido a tamanho superior a MAX_CLIENT_FRAME_SIZE!
[+] [Cliente] Desconexão segura executada no socket de teste 5.2.
[*] [Subteste 5.3] Validando tratamento de framing incorreto no leitor do cliente...
[+] SUCESSO: FramingError capturado corretamente no leitor.
[+] Desconexão segura executada no par de sockets local.
```

---

## 🧪 Testes de Segurança Embutidos

O script `main.py` orquestra a comunicação entre dois clientes reais e valida os requisitos mandatórios de segurança do sistema:

1. **Troca de Mensagens E2E (Sucesso):**
   - Alice e Bob realizam o handshake mútuo com validação de Certificate Pinning e RSA-PSS.
   - Ambos derivam as chaves simétricas E2E com base no `pair_salt` recebido via canal administrativo cifrado.
   - Mensagens cifradas com AES-128-GCM são transmitidas através do relay e decifradas com sucesso.
2. **Teste de Adulteração (Bitflip / Tampering no Tráfego):**
   - Um bit da tag de autenticação GCM do frame é alterado em trânsito.
   - O servidor repassa o frame cego ao destinatário.
   - O decifrador do destinatário rejeita o frame imediatamente devido à falha de integridade da Tag GCM.
3. **Teste de Replay Attack (seq_no já utilizado):**
   - Um frame com `seq_no` anterior é retransmitido na rede.
   - Tanto o servidor relay quanto o destinatário detectam a violação da monotonicidade de `seq_no` e rejeitam o pacote.
4. **Teste de Framing Inválido (Tamanho Incorreto) e Desconexão Segura:**
   - Validações contra tamanhos ilegais (comprimento 0 ou superior ao limite `MAX_CLIENT_FRAME_SIZE`).
   - Servidor e cliente tratam o erro de protocolo e realizam o encerramento seguro (`desconexao_segura`) dos sockets sem travamentos nem vazamentos de recursos.
