# ---- builder ----
FROM eclipse-temurin:17-jdk-focal AS builder
WORKDIR /app

# copy mvnw and maven wrapper and make executable
COPY mvnw .
COPY .mvn .mvn
RUN chmod +x mvnw

# copy pom and source
COPY pom.xml .
COPY src ./src

# build (skip tests to speed up CI, change if you want tests)
RUN ./mvnw -B -DskipTests package

# ---- runtime ----
FROM eclipse-temurin:17-jre-focal
WORKDIR /app

# copy jar from builder stage (adjust the wildcard if your artifactId/version differ)
COPY --from=builder /app/target/*.jar app.jar

EXPOSE 8080
ENTRYPOINT ["java","-jar","/app/app.jar"]
