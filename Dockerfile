# Use a imagem oficial do Python
FROM python:3.11-slim-buster

# Defina a variável de ambiente para que a saída python seja enviada diretamente
# para o terminal sem ser primeiro armazenada em buffer.
ENV PYTHONUNBUFFERED=1

# Crie um diretório de trabalho no contêiner
WORKDIR /app

# Copie o arquivo de requisitos para o contêiner
COPY requirements.txt /app

# Instale as dependências
RUN pip install --no-cache-dir -r requirements.txt

# Copie o código do aplicativo para o contêiner
COPY . /app

# # Exponha a porta em que a aplicação será executada
# EXPOSE 8000

CMD ["fastapi", "run", "app", "--host", "0.0.0.0", "--port", "80"]