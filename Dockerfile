FROM node:22-alpine
WORKDIR /app
COPY package*.json ./
RUN npm install --omit=dev
COPY src ./src
COPY db ./db
USER node
EXPOSE 3000
CMD ["npm", "start"]
