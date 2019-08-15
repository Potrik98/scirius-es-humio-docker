#FROM docker.elastic.co/logstash/logstash-oss:6.3.0
#FROM docker.elastic.co/logstash/logstash-oss:7.1.1
#FROM docker.elastic.co/logstash/logstash-oss:6.7.0
FROM docker.elastic.co/logstash/logstash-oss:6.8.1
#
USER root
#
#RUN yum install -y patch
#RUN yum install -y jq

# logstash.conf logs all input to output causing
# massive use of the processor when running using docker-compose up
RUN [ -f /usr/share/logstash/pipeline/logstash.conf ] \
    && rm /usr/share/logstash/pipeline/logstash.conf

# Add eve config.
# RUN mkdir -p /usr/share/logstash/pipeline
#ADD files/eve.conf /usr/share/logstash/pipeline/eve.conf.orig
ADD files/eve.conf /tmp/eve.conf.orig
#
ADD files/jq-linux64 /usr/local/bin/jq
ADD files/wait-for-it /usr/local/bin/wait-for-it
ADD files/pre-logstash-entrypoint /usr/local/bin/pre-logstash-entrypoint
RUN chown root:root /usr/local/bin/pre-logstash-entrypoint && chmod +x /usr/local/bin/pre-logstash-entrypoint
#
USER logstash

#ENTRYPOINT ["/usr/local/bin/pre-logstash-entrypoint"]
ENTRYPOINT ["/usr/local/bin/docker-entrypoint"]
