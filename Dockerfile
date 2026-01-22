
FROM node:18-alpine

# Security: Run as a non-privileged user
USER node 
WORKDIR /home/node/app

COPY --chown=node:node package*.json ./
RUN npm ci --only=production

COPY --chown=node:node . .

EXPOSE 3001
CMD ["npm", "start"]
