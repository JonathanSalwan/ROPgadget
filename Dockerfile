FROM python

LABEL MAINTAINER oddrabbit

RUN apt-get update \
        && python -m pip install ROPgadget

ENTRYPOINT ["ROPgadget"]
