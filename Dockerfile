FROM python:2.7-alpine

RUN apk --update add gcc  musl-dev linux-headers
RUN pip install flask_restful scapy netifaces requests
RUN mkdir /app
COPY *.py /app/

WORKDIR /app
CMD /app/dhcp-relay.py
