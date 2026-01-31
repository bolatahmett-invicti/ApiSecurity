// Sample Go Application - Demonstrates various Go web framework patterns

package main

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/mux"
	"github.com/labstack/echo/v4"
	"github.com/gofiber/fiber/v2"
)

// =============================================================================
// STANDARD LIBRARY (net/http)
// =============================================================================

func standardLibServer() {
	// Health endpoint
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"status": "healthy"})
	})

	// User endpoints
	http.HandleFunc("/api/users", handleUsers)
	http.HandleFunc("/api/users/", handleUserByID)
	
	// Admin endpoint - DANGER: No auth!
	http.HandleFunc("/admin/reset", handleAdminReset)

	// Start server
	log.Println("Starting server on :8080")
	http.ListenAndServe(":8080", nil)
}

func handleUsers(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		json.NewEncoder(w).Encode([]string{})
	case "POST":
		json.NewEncoder(w).Encode(map[string]int{"id": 1})
	}
}

func handleUserByID(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(map[string]string{"user": "data"})
}

func handleAdminReset(w http.ResponseWriter, r *http.Request) {
	// CRITICAL: Database reset with no authentication!
	json.NewEncoder(w).Encode(map[string]bool{"reset": true})
}

// =============================================================================
// GIN FRAMEWORK
// =============================================================================

func ginServer() {
	router := gin.Default()

	// Health check
	router.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "healthy"})
	})

	// API v1 group
	v1 := router.Group("/api/v1")
	{
		// User routes
		v1.GET("/users", getUsers)
		v1.GET("/users/:id", getUserByID)
		v1.POST("/users", createUser)
		v1.PUT("/users/:id", updateUser)
		v1.DELETE("/users/:id", deleteUser)

		// Payment routes - HIGH RISK
		v1.POST("/payments/charge", chargePayment)
		v1.GET("/payments/history", getPaymentHistory)
	}

	// Admin routes - CRITICAL
	admin := router.Group("/admin")
	{
		admin.DELETE("/users/:id", adminDeleteUser)
		admin.POST("/database/reset", adminResetDB)
	}

	router.Run(":8080")
}

func getUsers(c *gin.Context) {
	c.JSON(200, gin.H{"users": []string{}})
}

func getUserByID(c *gin.Context) {
	id := c.Param("id")
	// Returns PII: email, phone, ssn
	c.JSON(200, gin.H{
		"id":    id,
		"email": "user@example.com",
		"phone": "555-1234",
		"ssn":   "123-45-6789",
	})
}

func createUser(c *gin.Context) {
	c.JSON(201, gin.H{"id": 1})
}

func updateUser(c *gin.Context) {
	c.JSON(200, gin.H{"updated": true})
}

func deleteUser(c *gin.Context) {
	c.JSON(200, gin.H{"deleted": true})
}

func chargePayment(c *gin.Context) {
	// Handles credit_card data
	c.JSON(200, gin.H{"transaction_id": "txn_123"})
}

func getPaymentHistory(c *gin.Context) {
	c.JSON(200, gin.H{"transactions": []string{}})
}

func adminDeleteUser(c *gin.Context) {
	c.JSON(200, gin.H{"deleted": true})
}

func adminResetDB(c *gin.Context) {
	c.JSON(200, gin.H{"reset": true})
}

// =============================================================================
// ECHO FRAMEWORK
// =============================================================================

func echoServer() {
	e := echo.New()

	// Health
	e.GET("/health", func(c echo.Context) error {
		return c.JSON(200, map[string]string{"status": "healthy"})
	})

	// API routes
	e.GET("/api/products", getProducts)
	e.GET("/api/products/:id", getProductByID)
	e.POST("/api/products", createProduct)
	e.PUT("/api/products/:id", updateProduct)
	e.DELETE("/api/products/:id", deleteProduct)

	// Auth routes
	e.POST("/auth/login", login)
	e.POST("/auth/register", register)

	e.Start(":8080")
}

// =============================================================================
// FIBER FRAMEWORK
// =============================================================================

func fiberServer() {
	app := fiber.New()

	// Health
	app.Get("/health", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"status": "healthy"})
	})

	// Orders API
	app.Get("/api/orders", getOrders)
	app.Get("/api/orders/:id", getOrderByID)
	app.Post("/api/orders", createOrder)
	app.Put("/api/orders/:id", updateOrder)
	app.Delete("/api/orders/:id", deleteOrder)

	app.Listen(":8080")
}

// =============================================================================
// GORILLA MUX
// =============================================================================

func gorillaMuxServer() {
	router := mux.NewRouter()

	// Health
	router.HandleFunc("/health", healthHandler).Methods("GET")

	// API subrouter
	api := router.PathPrefix("/api/v2").Subrouter()
	api.HandleFunc("/customers", getCustomers).Methods("GET")
	api.HandleFunc("/customers/{id}", getCustomerByID).Methods("GET")
	api.HandleFunc("/customers", createCustomer).Methods("POST")
	api.HandleFunc("/customers/{id}", updateCustomer).Methods("PUT")
	api.HandleFunc("/customers/{id}", deleteCustomer).Methods("DELETE")

	// Billing - HIGH RISK
	api.HandleFunc("/billing/invoices", getInvoices).Methods("GET")
	api.HandleFunc("/billing/charge", chargeBilling).Methods("POST")

	http.ListenAndServe(":8080", router)
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func getCustomers(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode([]string{})
}

func getCustomerByID(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	json.NewEncoder(w).Encode(map[string]string{"id": vars["id"]})
}

func createCustomer(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(map[string]int{"id": 1})
}

func updateCustomer(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(map[string]bool{"updated": true})
}

func deleteCustomer(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(map[string]bool{"deleted": true})
}

func getInvoices(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode([]string{})
}

func chargeBilling(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(map[string]string{"transaction_id": "txn_456"})
}

// =============================================================================
// MAIN
// =============================================================================

func main() {
	// Choose which server to run
	ginServer()
}
