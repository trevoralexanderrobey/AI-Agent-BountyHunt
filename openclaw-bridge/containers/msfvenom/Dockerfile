FROM kalilinux/kali-rolling@sha256:97dc10a70377ccb7227d3fedfc7132f9f45aeb9167189622e715df0c613f7f6f

ENV DEBIAN_FRONTEND=noninteractive
WORKDIR /opt/openclaw

RUN apt-get update   && apt-get install -y --no-install-recommends ca-certificates nodejs metasploit-framework   && apt-get clean   && rm -rf /var/lib/apt/lists/*

RUN groupadd --system openclaw   && useradd --system --gid openclaw --home /home/openclaw --create-home openclaw

COPY runtime /opt/openclaw/runtime
COPY tools /opt/openclaw/tools
COPY execution /opt/openclaw/execution

ENV NODE_ENV=production
ENV OPENCLAW_REQUEST_PATH=/scratch/request.json
ENV OPENCLAW_TOOL_SLUG=msfvenom

RUN mkdir -p /scratch /scratch/tmp   && chown -R openclaw:openclaw /opt/openclaw /scratch

USER openclaw

ENTRYPOINT ["node", "/opt/openclaw/runtime/container-tool-runner.js"]
