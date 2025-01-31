package main

import (
	"a10_solver/pkg/a10_client"
	"fmt"
	"log"
	"os"
	"strconv"

	"github.com/joho/godotenv"
)

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatalf("Error loading .env file")
	}
	host := os.Getenv("A10_IP_ADDRESS")
	username := os.Getenv("A10_USERNAME")
	password := os.Getenv("A10_PASSWORD")
	if host == "" || username == "" || password == "" {
		log.Fatalf("Environment variables A10_IP_ADDRESS, A10_USERNAME, and A10_PASSWORD must be set")
	}
	client := a10_client.NewA10Client(host, username, password)
	err = client.Login()
	if err != nil {
		log.Fatalf("Failed to login: %v", err)
	}
	zone := os.Getenv("A10_ZONE")
	if zone == "" {
		log.Fatal("A10_ZONE not set")
	}
	recordName := "_acme-challenge"
	recordValue := "your-txt-record-value"
	a10_dns_port := os.Getenv("A10_DNS_PORT")
	a10_service := os.Getenv("A10_SERVICE")
	a10_dns_ttl := os.Getenv("A10_DNS_TTL")
	ttl, err := strconv.Atoi(a10_dns_ttl)
	if err != nil {
		log.Fatalf("Invalid A10_DNS_TTL value: %v", err)
	}

	servicePortAndName := fmt.Sprintf("%s+%s", a10_dns_port, a10_service)

	err = client.CreateTXTRecord(zone, servicePortAndName, recordName, recordValue, ttl)
	if err != nil {
		log.Fatalf("Failed to update TXT record: %v", err)
	}

	fmt.Println("TXT record created successfully")
}


