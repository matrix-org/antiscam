FROM python:2.7-slim-stretch AS builder
WORKDIR /app

RUN apt-get update && apt-get -y upgrade && apt-get -y install gcc
COPY . /app
RUN python setup.py build
RUN pip install -r requirements.txt

FROM python:2.7-slim-stretch
WORKDIR /app

COPY . /app
COPY --from=builder /usr/local/lib/python2.7/site-packages/. /usr/local/lib/python2.7/site-packages

CMD ["python", "bot.py"]
