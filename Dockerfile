FROM python:3.9

WORKDIR /app

COPY ../api .

# Installation des dépendances sécurisées
RUN pip install flask bcrypt werkzeug

EXPOSE 5000

CMD ["python", "app.py"]
