FROM openjdk:17-jdk-slim AS build
WORKDIR /app
COPY gradlew gradlew.bat ./
COPY gradle/ gradle/
COPY build.gradle ./
RUN chmod +x gradlew
COPY src/ src/
RUN ./gradlew jar shadowJar --no-daemon

FROM quay.io/keycloak/keycloak:26.3.3
RUN mkdir -p /opt/keycloak/providers/
COPY --from=build /app/build/libs/*-all.jar /opt/keycloak/providers/
CMD start-dev
