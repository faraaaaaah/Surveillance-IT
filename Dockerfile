FROM registry.access.redhat.com/ubi9/python-312

WORKDIR /opt/app-root/src

COPY --chown=1001:0 requirement.txt .
RUN pip install --no-cache-dir -r requirement.txt

COPY --chown=1001:0 . .

ENV PORT=8080
EXPOSE 8080

CMD ["python", "dash.py"]