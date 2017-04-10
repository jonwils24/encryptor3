FROM python:2.7

WORKDIR /usr/src/app

COPY . /usr/src/app

VOLUME ["/usr/src/app/downloaded_file"]

RUN mkdir /root/.aws
COPY ./credentials /root/.aws/credentials

RUN pip install --no-cache-dir -r requirements.txt

CMD ["python", "/usr/src/app/run.py"]
