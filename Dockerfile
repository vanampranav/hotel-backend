FROM gradle:7.6.1-jdk17-alpine AS build
WORKDIR /home/gradle/src
COPY --chown=gradle:gradle . .
RUN gradle bootJar --no-daemon

FROM eclipse-temurin:17-jdk-alpine
WORKDIR /app
COPY --from=build /home/gradle/src/build/libs/HotelManagement.jar app.jar

# Install curl for network diagnostics
RUN apk add --no-cache curl iputils

# Environment variables with defaults
ENV PORT=8080
ENV JAVA_OPTS=""

# Expose the port - use both fixed port and variable
EXPOSE 8080

# Add a startup script to help with debugging
RUN echo '#!/bin/sh' > /app/startup.sh && \
    echo 'echo "Starting application with port: $PORT"' >> /app/startup.sh && \
    echo 'echo "Java options: $JAVA_OPTS"' >> /app/startup.sh && \
    echo 'echo "Working directory: $(pwd)"' >> /app/startup.sh && \
    echo 'echo "Files in app directory:"' >> /app/startup.sh && \
    echo 'ls -la /app' >> /app/startup.sh && \
    echo 'echo "Network interfaces:"' >> /app/startup.sh && \
    echo 'ip addr || ifconfig || echo "No network tools available"' >> /app/startup.sh && \
    echo 'echo "Checking localhost connectivity:"' >> /app/startup.sh && \
    echo 'timeout 2 curl -v http://localhost:8080/ || echo "Cannot connect to localhost"' >> /app/startup.sh && \
    echo 'echo "Starting application..."' >> /app/startup.sh && \
    echo 'java -jar $JAVA_OPTS -Dserver.address=0.0.0.0 -Dserver.port=8080 -Dspring.profiles.active=prod /app/app.jar' >> /app/startup.sh && \
    chmod +x /app/startup.sh

ENTRYPOINT ["/app/startup.sh"] 