FROM kali-rolling

ENV DEBIAN_FRONTEND=noninteractive
WORKDIR /app

RUN apt-get update \
  && apt-get install -y --no-install-recommends nmap nodejs ca-certificates \
  && adduser --system --group --home /home/openclaw openclaw \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/*

COPY runtime /app/runtime
COPY runtime/mcp-skill-server.js /app/runtime/mcp-skill-server.js

RUN chown -R openclaw:openclaw /app

ENV NODE_ENV=production
ENV TOOL_NAME=nmap
ENV SKILL_SLUG=nmap
ENV PORT=4000

USER openclaw

EXPOSE 4000

CMD ["node", "runtime/mcp-skill-server.js"]
