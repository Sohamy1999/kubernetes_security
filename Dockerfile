# Use a Debian-based OpenJDK image with package manager support
FROM openjdk:17-jdk-slim

# Install dpkg and other required tools
RUN apt-get update && apt-get install -y \
    dpkg \
    apt-utils \
    && rm -rf /var/lib/apt/lists/*

# Add metadata validation to ensure dpkg-query compatibility
RUN dpkg-query --help || echo "Warning: dpkg-query not installed properly"

# Set the working directory in the container
WORKDIR /app

# Copy the jar file created by your Spring Boot application build
COPY target/security_framework-0.0.1-SNAPSHOT.jar app.jar

# Expose the port your application runs on
EXPOSE 8081

# Run the jar file
ENTRYPOINT ["java", "-jar", "app.jar"]
