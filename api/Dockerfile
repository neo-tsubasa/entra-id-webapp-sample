FROM python:3.11-slim

WORKDIR /code

ARG COPY_FROM
ARG COPY_TO
ARG SERVER_OPTIONS

ENV SERVER_OPTIONS ${SERVER_OPTIONS}

COPY ${COPY_FROM} ${COPY_TO}

RUN pip install --no-cache-dir --upgrade -r /code/requirements.txt

CMD flask run --host 0.0.0.0 ${SERVER_OPTIONS}
