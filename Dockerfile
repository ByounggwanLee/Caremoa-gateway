FROM openjdk:11 as build
COPY /build/libs/*SNAPSHOT.jar app.jar
EXPOSE 8080
ENTRYPOINT ["java","-Xmx400M","-jar","/app.jar","--spring.profiles.active=docker"]