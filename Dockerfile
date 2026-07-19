FROM registry.access.redhat.com/ubi9/python-312

WORKDIR /opt/app-root/src

COPY requirement.txt .
RUN pip install --no-cache-dir -r requirement.txt

COPY . .

# Corrige les permissions pour l'utilisateur non-root d'OpenShift
RUN chmod -R g=u /opt/app-root/src

ENV PORT=8080
EXPOSE 8080

CMD ["python", "dash.py"]