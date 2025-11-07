# Build stage: compile the Go application
FROM golang:latest as build

WORKDIR /app

# Copy the Go module files
COPY go.mod ./
COPY main.go ./

# Download the Go module dependencies
RUN go mod download

COPY . .

# Build
RUN CGO_ENABLED=0 GOOS=linux go build -o /docker-gs-ping


# Final stage: a minimal image to run the application
FROM alpine:latest as run

WORKDIR /app

# Copy the application executable from the build image
COPY --from=build /docker-gs-ping ./

EXPOSE 8080
CMD ["./docker-gs-ping"]
