FROM python:latest

ADD code /code
RUN pip3 install -r /code/pip-requirements.txt

WORKDIR /code
ENV PYTHONPATH '/code/'

EXPOSE 8125

CMD ["python" , "/code/collector.py"]