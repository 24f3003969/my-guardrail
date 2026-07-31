FROM node:20-slim
WORKDIR /app
RUN mkdir -p /srv/agent-redteam/outside-5459cf9e \
    /srv/agent-redteam/sandbox-ad091e9eba/notes \
    /srv/agent-redteam/sandbox-ad091e9eba/encoded && \
    chmod -R 777 /srv/agent-redteam
COPY package.json ./
RUN npm install --production
COPY index.js ./
ENV PORT=3000
EXPOSE 3000
CMD ["node", "index.js"]