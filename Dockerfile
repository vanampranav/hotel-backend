FROM eclipse-temurin:17-jdk-alpine

WORKDIR /app

# First build the application
COPY . .
RUN ./gradlew bootJar --no-daemon

# Move the JAR file
RUN mkdir -p build/libs
RUN ls -la build/libs || echo "Directory empty"
RUN cp build/libs/HotelManagement.jar app.jar || echo "JAR not found, finding it..." && find / -name "*.jar" | grep -v ".gradle" 2>/dev/null || echo "No JARs found"

EXPOSE 8080

ENTRYPOINT ["java", "-jar", "/app/app.jar"] 