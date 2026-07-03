# syntax=docker/dockerfile:1

# --- Build stage: compile the fat JAR with Gradle + JDK 21 ---
FROM eclipse-temurin:21-jdk-jammy AS build
WORKDIR /workspace

COPY gradlew gradlew.bat ./
COPY gradle ./gradle
COPY settings.gradle.kts build.gradle.kts ./
COPY core ./core
COPY connectors ./connectors
COPY reachability ./reachability
COPY enrich ./enrich
COPY scoring ./scoring
COPY advisor ./advisor
COPY output ./output
COPY cmd ./cmd
COPY fixtures ./fixtures

RUN chmod +x gradlew && ./gradlew --no-daemon :cmd:shadowJar

# --- Runtime stage: slim JRE + the fat JAR only ---
FROM eclipse-temurin:21-jre-jammy
WORKDIR /app

COPY --from=build /workspace/cmd/build/libs/cmd-all.jar /app/reachlayer.jar

ENTRYPOINT ["java", "-jar", "/app/reachlayer.jar"]
