FROM docker.elastic.co/logstash/logstash-oss:6.2.4

RUN echo "-XX:+AssumeMP" >> /usr/share/logstash/config/jvm.options
RUN echo "-XX:ParallelGCThreads=10" >> /usr/share/logstash/config/jvm.options

RUN /usr/share/logstash/bin/logstash-plugin install logstash-output-kafka
RUN /usr/share/logstash/bin/logstash-plugin install logstash-input-tcp
#RUN /usr/share/logstash/bin/logstash-plugin install logstash-input-udp
RUN /usr/share/logstash/bin/logstash-plugin install logstash-codec-json
RUN /usr/share/logstash/bin/logstash-plugin install logstash-filter-grok
#RUN /usr/share/logstash/bin/logstash-plugin install logstash-filter-json
#RUN /usr/share/logstash/bin/logstash-plugin install logstash-filter-dns
#RUN /usr/share/logstash/bin/logstash-plugin install logstash-filter-geoip
RUN /usr/share/logstash/bin/logstash-plugin install logstash-filter-mutate
RUN /usr/share/logstash/bin/logstash-plugin install logstash-filter-date
RUN /usr/share/logstash/bin/logstash-plugin install logstash-filter-translate

RUN rm -f /config/logstash.yml
COPY config/logstash.yml config/logstash.yml


RUN rm -f /usr/share/logstash/pipeline/logstash.conf
ADD pipeline/ /usr/share/logstash/pipeline/
ADD pattern.txt /usr/share/logstash/
