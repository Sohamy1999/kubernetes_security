# Use a Debian-based OpenJDK image with apt-get support
FROM openjdk:17-buster

# Install dpkg and other required tools
RUN apt-get update && apt-get install -y \
    dpkg \
    apt-utils \
    && rm -rf /var/lib/apt/lists/

# Set the working directory in the container
WORKDIR /app

# Copy the JAR file created by your Spring Boot application build
COPY target/security_framework-0.0.1-SNAPSHOT.jar app.jar

# Expose the port your application runs on
EXPOSE 8081

# Run the JAR file
ENTRYPOINT ["java", "-jar", "app.jar"]
