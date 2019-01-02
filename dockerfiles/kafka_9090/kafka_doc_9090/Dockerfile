FROM netflixoss/java:8

ENV KAFKA_VERSION=2.1.0 KAFKA_SCALA_VERSION=2.11
ENV KAFKA_RELEASE_ARCHIVE kafka_${KAFKA_SCALA_VERSION}-${KAFKA_VERSION}.tgz

RUN mkdir /kafka /data /logs

RUN apt-get update && \
  DEBIAN_FRONTEND=noninteractive apt-get install -y \
    ca-certificates

ADD http://www.us.apache.org/dist/kafka/${KAFKA_VERSION}/${KAFKA_RELEASE_ARCHIVE} /tmp/
ADD https://dist.apache.org/repos/dist/release/kafka/${KAFKA_VERSION}/${KAFKA_RELEASE_ARCHIVE}.md5 /tmp/

WORKDIR /tmp

RUN echo VERIFY CHECKSUM: && \
  gpg --print-md MD5 ${KAFKA_RELEASE_ARCHIVE} 2>/dev/null && \
  cat ${KAFKA_RELEASE_ARCHIVE}.md5

RUN tar -zx -C /kafka --strip-components=1 -f ${KAFKA_RELEASE_ARCHIVE} && \
  rm -rf kafka_*

ADD config /kafka/config
ADD start.sh /kafka/start.sh

RUN chmod +x /kafka/start.sh

RUN groupadd jakekafka && \
  useradd -d /kafka -g jakekafka -s /bin/false jakekafka && \
  chown -R jakekafka /kafka /data /logs
USER jakekafka
ENV PATH /kafka/bin:$PATH
WORKDIR /kafka

EXPOSE 9090

CMD ["/kafka/start.sh"]
