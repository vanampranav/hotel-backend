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
ENV JAVA_OPTS="-Xmx512m -Xms256m"

# Expose the port
EXPOSE 8080

# Create simple healthcheck endpoint 
RUN mkdir -p /app/public && \
    echo '{"status":"UP"}' > /app/public/health.json && \
    echo '<!DOCTYPE html><html><body><h1>Hotel Management API</h1><p>Service is running</p></body></html>' > /app/public/index.html

# Add a startup script
RUN echo '#!/bin/sh' > /app/startup.sh && \
    echo 'echo "Starting application with port: $PORT"' >> /app/startup.sh && \
    echo 'echo "Java options: $JAVA_OPTS"' >> /app/startup.sh && \
    echo 'echo "Working directory: $(pwd)"' >> /app/startup.sh && \
    echo 'echo "Files in app directory:"' >> /app/startup.sh && \
    echo 'ls -la /app' >> /app/startup.sh && \
    echo 'echo "Network interfaces:"' >> /app/startup.sh && \
    echo 'ip addr || ifconfig || echo "No network tools available"' >> /app/startup.sh && \
    echo 'echo "Starting Spring Boot application in foreground mode"' >> /app/startup.sh && \
    echo 'java -jar $JAVA_OPTS -Dserver.address=0.0.0.0 -Dserver.port=8080 -Dspring.profiles.active=prod -XX:+CrashOnOutOfMemoryError -XX:+HeapDumpOnOutOfMemoryError -XX:HeapDumpPath=/tmp /app/app.jar' >> /app/startup.sh && \
    chmod +x /app/startup.sh

ENTRYPOINT ["/app/startup.sh"] 