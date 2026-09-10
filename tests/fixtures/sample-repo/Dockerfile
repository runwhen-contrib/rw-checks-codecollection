FROM ubuntu:latest
RUN apt-get update
RUN apt-get install -y curl
ADD http://example.com/file.tar.gz /tmp/
COPY . /app
WORKDIR /app
RUN cd /app && pip install requests
USER root
CMD python app.py
