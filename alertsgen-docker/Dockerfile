FROM debian

RUN apt-get update && apt-get install -y python3-pip python3
ADD files /app
WORKDIR /app
RUN pip3 install -r requirements.txt

ENTRYPOINT ["/usr/bin/python3", "/app/alertsgen.py", "$TOKEN"]
