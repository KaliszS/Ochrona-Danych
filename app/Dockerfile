FROM python:3

WORKDIR /app

ENV FLASK_APP app.py
ENV FLASK_RUN_HOST 0.0.0.0
ENV FLASK_RUN_PORT 80

COPY . /app

RUN pip install -r requirements.txt
RUN pip install pyopenssl

CMD ["flask", "run", "--cert=project.crt", "--key=project.key"]