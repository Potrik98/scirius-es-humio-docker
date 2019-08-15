#!/bin/sh
[ -z "$SCIRIUS_DIR" ] && SCIRIUS_DIR="scirius"

echo "=> Copying scirius from $SCIRIUS_DIR into current directory"
rsync -ra "$SCIRIUS_DIR" . || exit "$?"

echo "=> Extracting requirements.txt"
cp "${SCIRIUS_DIR}/requirements.txt" requirements.txt || exit "$?"

APT_PACKAGES="wget python-pip python-dev git gcc gunicorn tcpdump gnupg2 patch"
echo "=> Generating Dockerfile"
cat > Dockerfile <<EOF
FROM debian:latest

RUN apt-get update \
  && DEBIAN_FRONTEND=noninteractive apt-get install --no-install-recommends -y \
  $APT_PACKAGES \
  && mkdir /scirius

ADD scirius/requirements.txt /tmp/requirements.txt
RUN pip install -r /tmp/requirements.txt

ADD ./scirius /app/scirius
WORKDIR /app/scirius
RUN mkdir /var/log/scirius && touch /var/log/scirius/elasticsearch.log

ENTRYPOINT ["python", "manage.py", "runserver", "0.0.0.0:8000"]
EOF

echo "=> Building base docker image scirius"
docker build -t scirius:base . || exit "$?"

cat > Dockerfile <<EOF
FROM scirius:base
ADD settings_humio.py /app/scirius/scirius/settings.py
ENTRYPOINT ["python", "manage.py", "runserver", "0.0.0.0:8008"]
EOF

echo "=> Building docker image for humio"
docker build -t scirius:humio . || exit "$?"

cat > Dockerfile <<EOF
FROM scirius:base
ADD settings_es.py /app/scirius/scirius/settings.py
ENTRYPOINT ["python", "manage.py", "runserver", "0.0.0.0:8009"]
EOF

echo "=> Building docker image for es"
docker build -t scirius:es . || exit "$?"

cat > Dockerfile <<EOF
FROM scirius:base
ADD settings_alertsgen.py /app/scirius/scirius/settings.py
# create_default_token is the command used to generate a predictable
# token: d292d0af257f5887c1404f73ad50bd36d27ca3f1
# used by alertsgen
ADD create_default_token.py /app/scirius/rules/management/commands/create_default_token.py
RUN python manage.py create_default_token
ENTRYPOINT ["python", "manage.py", "runserver", "0.0.0.0:8007"]
EOF

echo "=> Building docker image for alertsgen"
docker build -t scirius:alertsgen . || exit "$?"
