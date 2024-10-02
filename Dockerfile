FROM node:slim
WORKDIR /server
COPY . /server
RUN npm install
EXPOSE 8000
CMD node index.js