FROM docker.io/python:3.14.3-alpine3.23

WORKDIR /selfproxy

COPY ./requirements.txt /selfproxy/requirements.txt

RUN pip install --no-cache-dir pip==26.0.1 && \
    pip install --no-cache-dir --upgrade -r /selfproxy/requirements.txt

COPY ./app /selfproxy/app

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD wget -qO- http://localhost:80/health || exit 1

USER selfproxy

CMD ["fastapi", "run", "app/main.py", "--port", "80"]