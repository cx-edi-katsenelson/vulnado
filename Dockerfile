FROM eclipse-temurin:17-jdk

RUN apt-get update && \
    apt-get install build-essential maven cowsay netcat -y
COPY . .

CMD ["mvn", "spring-boot:run"]

FROM debian:10
RUN apt-get update && apt-get install -y curl vim git
