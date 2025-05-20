FROM gradle:7.6.1-jdk17-alpine AS build
WORKDIR /home/gradle/src
COPY --chown=gradle:gradle . .
RUN gradle bootJar --no-daemon

FROM eclipse-temurin:17-jdk-alpine
WORKDIR /app
COPY --from=build /home/gradle/src/build/libs/HotelManagement.jar app.jar

# Environment variables with defaults
ENV PORT=8080
ENV JAVA_OPTS=""

# Expose the port
EXPOSE ${PORT}

# Add a startup script to help with debugging
RUN echo '#!/bin/sh' > /app/startup.sh && \
    echo 'echo "Starting application with port: $PORT"' >> /app/startup.sh && \
    echo 'echo "Java options: $JAVA_OPTS"' >> /app/startup.sh && \
    echo 'echo "Working directory: $(pwd)"' >> /app/startup.sh && \
    echo 'echo "Files in app directory:"' >> /app/startup.sh && \
    echo 'ls -la /app' >> /app/startup.sh && \
    echo 'echo "Starting application..."' >> /app/startup.sh && \
    echo 'java -jar $JAVA_OPTS -Dspring.profiles.active=prod -Dserver.port=$PORT /app/app.jar' >> /app/startup.sh && \
    chmod +x /app/startup.sh

ENTRYPOINT ["/app/startup.sh"] 