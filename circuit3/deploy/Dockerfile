FROM ubuntu

RUN mkdir /c3 \
    && apt-get -y  update \
    && apt-get -y  upgrade \
    && apt-get -y install python3 \
    && apt-get -y install python3-pip

WORKDIR /c3

ADD ./c3.py /c3/c3.py
ADD ./flag.txt /c3/flag.txt

CMD ["python3", "/c3/c3.py"]

EXPOSE 10087