FROM docker.elastic.co/elasticsearch/elasticsearch-oss:6.2.4

RUN echo "-XX:+AssumeMP" >> /usr/share/elasticsearch/config/jvm.options
RUN echo "-XX:ParallelGCThreads=10" >> /usr/share/elasticsearch/config/jvm.options
