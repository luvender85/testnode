FROM node:13.8.0-buster

WORKDIR /app
COPY /. ./

RUN npm install

EXPOSE 3000
ENTRYPOINT ["npm", "start"]