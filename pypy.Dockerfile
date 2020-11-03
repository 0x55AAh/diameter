FROM pypy:3-7

RUN mv /usr/bin/python /usr/bin/python.old
RUN ln -s /usr/local/bin/pypy3 /usr/bin/python

RUN mkdir -p /usr/src/app
WORKDIR /usr/src/app

COPY requirements.txt /usr/src/app/
RUN pip install --upgrade pip
RUN pip install --no-cache-dir -r requirements.txt

COPY . /usr/src/app

#RUN useradd appuser
#RUN chown -R appuser /usr/src/app
#USER appuser