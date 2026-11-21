# eyesonly-server: auth proxy + policy enforcement. Put TLS in front of it.
#   docker build -t eyesonly .
#   docker run -d -p 8787:8787 -v eyesonly-data:/data eyesonly
#   docker exec -it <container> eyesonly-server init --admin eyesonlypub1:... --repo app.git
#   or, with the compose kit: see deploy/README.md
FROM node:24-alpine
RUN apk add --no-cache git
WORKDIR /app
COPY package.json LICENSE ./
COPY bin ./bin
COPY src ./src
COPY site ./site
RUN npm link && adduser -D -h /data eyesonly && mkdir -p /data && chown eyesonly /data && chmod 700 /data
USER eyesonly
ENV EYESONLY_DATA=/data HOME=/data
VOLUME /data
EXPOSE 8787
HEALTHCHECK CMD wget -qO- http://127.0.0.1:8787/healthz || exit 1
CMD ["eyesonly-server", "serve", "--host", "0.0.0.0", "--port", "8787"]
