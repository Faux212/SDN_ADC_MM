FROM grafana/grafana

COPY grafana/ /usr/share/

COPY grafana_var/ /var/lib/grafana

USER root

RUN chown -R grafana /var/lib/grafana
