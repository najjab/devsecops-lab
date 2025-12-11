FROM python:3.9-alpine

WORKDIR /app

# Installer les dépendances nécessaires (build + crypto)
RUN apk add --no-cache \
    build-base \
    libffi-dev \
    openssl-dev

COPY ../api .

RUN pip install --no-cache-dir flask bcrypt werkzeug

EXPOSE 5000

CMD ["python", "app.py"]
