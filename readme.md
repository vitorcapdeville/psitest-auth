# Serviço de autenticação

Este serviço é responsável por realizar a autenticação dos usuários do PsiTest. Ele se comunico com um banco de dados para armazenar as credenciais de usuários e possíveis códigos de verificação de e-mail e reset de password.

São expostas rotas para realizar login, cadastro, verificação de e-mail e reset de senha. A comunicação com os usuários é delegada para o serviço de e-mail.

Antes de utilizar o serviço, crie um arquivo `.env` com as seguintes variáveis:

- SECRET_KEY - Chave para realizar o encode do JWT.
- ALGORITHM - Algoritmo de encode do JWT.
- ACCESS_TOKEN_EXPIRE_MINUTES - Tempo em minutos até a expiração do JWT.
- PSITEST_EMAILS - URL para o serviço de envio de e-mail.

> NOTA: É necessário que o serviço de e-mail esteja disponível para a utilização deste serviço.

## Instalação local

Para utilizar o serviço localmente, é recomendado a criação de um ambiente virtual.

```bash
python -m venv .venv
.venv/scripts/activate
```

Após a criação do ambiente virtual, instale as dependências do projeto.

```bash
pip install -r requirements.txt
```

### Execução

Para executar o servidor, utilize o comando:

```bash
fastapi run app
```

O servidor estará disponível em `http://localhost:8000`.

## Utilizando via Docker

Para executar via Docker, é necessário ter o Docker instalado e em execução. Também é necessário que exista uma rede chamada `psitest`. A rede deve ser criada uma única vez com o seguinte comando:

```bash
docker network create psitest
```

Após a criação da rede, execute o seguinte comando para criar a imagem do serviço:

```bash
docker compose up
```

O serviço estará disponível em `http://localhost:8002`.

