FROM openjdk:17-jdk-slim AS build
WORKDIR /app
COPY gradlew gradlew.bat ./
COPY gradle/ gradle/
COPY build.gradle ./
RUN chmod +x gradlew
COPY src/ src/
RUN ./gradlew jar shadowJar --no-daemon

FROM bitnami/keycloak:26.3.3
COPY --from=build /app/build/libs/*-all.jar /opt/bitnami/keycloak/providers/keycloak-scim-1.0-SNAPSHOT-all.jar
RUN kc.sh build
CMD ["/opt/bitnami/scripts/keycloak/run.sh"]
