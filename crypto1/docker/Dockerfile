FROM ubuntu

ENV DEBIAN_FRONTEND=noninteractive

RUN mkdir -p /crypto/ \
    && apt-get update \
    && apt-get -y install cmake git build-essential libssl-dev libgmp-dev libboost-all-dev

COPY ./* /crypto/

WORKDIR /crypto/

EXPOSE 10086

CMD [ "./restart.sh" ]