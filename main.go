package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// ProxyRequest представляет структуру входящего прокси-запроса
type ProxyRequest struct {
	Method  string            `json:"method"`  // GET, POST, PUT, DELETE, etc.
	URL     string            `json:"url"`     // Целевой URL
	Headers map[string]string `json:"headers"` // HTTP заголовки
	Body    string            `json:"body"`    // Тело запроса (base64 для бинарных данных)
	Timeout int               `json:"timeout"` // Таймаут в секундах (по умолчанию 30)
}

// ProxyResponse представляет структуру ответа прокси
type ProxyResponse struct {
	StatusCode int               `json:"status_code"`
	Headers    map[string]string `json:"headers"`
	Body       string            `json:"body"`
	Error      string            `json:"error,omitempty"`
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	http.HandleFunc("/", proxyHTTP)
	http.HandleFunc("/health", healthCheck)

	log.Printf("Server starting on port %s", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}

// healthCheck - проверка здоровья сервиса
func healthCheck(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "healthy"})
}

// proxyHTTP - основная функция прокси
func proxyHTTP(w http.ResponseWriter, r *http.Request) {
	// Устанавливаем CORS заголовки
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	w.Header().Set("Content-Type", "application/json")

	// Обрабатываем preflight запросы
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	// Принимаем только POST запросы
	if r.Method != "POST" {
		sendErrorResponse(w, http.StatusMethodNotAllowed, "Only POST method is allowed")
		return
	}

	// Читаем тело запроса
	body, err := io.ReadAll(r.Body)
	if err != nil {
		sendErrorResponse(w, http.StatusBadRequest, "Failed to read request body")
		return
	}
	defer r.Body.Close()

	// Парсим JSON
	var proxyReq ProxyRequest
	if err := json.Unmarshal(body, &proxyReq); err != nil {
		sendErrorResponse(w, http.StatusBadRequest, "Invalid JSON format")
		return
	}

	// Валидируем запрос
	if err := validateProxyRequest(&proxyReq); err != nil {
		sendErrorResponse(w, http.StatusBadRequest, err.Error())
		return
	}

	// Выполняем прокси-запрос
	response := executeProxyRequest(&proxyReq)

	// Отправляем ответ
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// validateProxyRequest валидирует входящий прокси-запрос
func validateProxyRequest(req *ProxyRequest) error {
	if req.Method == "" {
		return fmt.Errorf("method is required")
	}

	// Проверяем допустимые HTTP методы
	allowedMethods := map[string]bool{
		"GET": true, "POST": true, "PUT": true, "DELETE": true,
		"PATCH": true, "HEAD": true, "OPTIONS": true,
	}
	if !allowedMethods[strings.ToUpper(req.Method)] {
		return fmt.Errorf("unsupported HTTP method: %s", req.Method)
	}

	if req.URL == "" {
		return fmt.Errorf("url is required")
	}

	// Парсим и валидируем URL
	parsedURL, err := url.Parse(req.URL)
	if err != nil {
		return fmt.Errorf("invalid URL format: %v", err)
	}

	// Проверяем схему
	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		return fmt.Errorf("only http and https schemes are allowed")
	}

	// Блокируем локальные адреса для безопасности
	if isLocalAddress(parsedURL.Hostname()) {
		return fmt.Errorf("requests to local addresses are not allowed")
	}

	// Проверяем длину URL
	if len(req.URL) > 2048 {
		return fmt.Errorf("URL too long (max 2048 characters)")
	}

	// Проверяем размер тела запроса
	if len(req.Body) > 1024*1024 { // 1MB
		return fmt.Errorf("request body too large (max 1MB)")
	}

	// Проверяем количество заголовков
	if len(req.Headers) > 50 {
		return fmt.Errorf("too many headers (max 50)")
	}

	// Устанавливаем таймаут по умолчанию
	if req.Timeout <= 0 {
		req.Timeout = 30
	}

	// Ограничиваем максимальный таймаут
	if req.Timeout > 300 {
		req.Timeout = 300
	}

	return nil
}

// isLocalAddress проверяет, является ли адрес локальным
func isLocalAddress(hostname string) bool {
	localAddresses := []string{
		"localhost", "127.0.0.1", "::1",
		"0.0.0.0", "169.254.", "10.", "172.16.", "192.168.",
	}

	hostname = strings.ToLower(hostname)
	for _, local := range localAddresses {
		if strings.HasPrefix(hostname, local) {
			return true
		}
	}

	return false
}

// executeProxyRequest выполняет HTTP запрос
func executeProxyRequest(proxyReq *ProxyRequest) *ProxyResponse {
	// Создаем HTTP клиент с таймаутом
	client := &http.Client{
		Timeout: time.Duration(proxyReq.Timeout) * time.Second,
	}

	// Создаем запрос
	var reqBody io.Reader
	if proxyReq.Body != "" {
		reqBody = strings.NewReader(proxyReq.Body)
	}

	req, err := http.NewRequest(proxyReq.Method, proxyReq.URL, reqBody)
	if err != nil {
		return &ProxyResponse{
			StatusCode: 500,
			Error:      fmt.Sprintf("Failed to create request: %v", err),
		}
	}

	// Добавляем заголовки
	for key, value := range proxyReq.Headers {
		// Фильтруем потенциально опасные заголовки
		if isSafeHeader(key) {
			req.Header.Set(key, value)
		}
	}

	// Добавляем User-Agent по умолчанию если не указан
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", "ProxyFunction/1.0")
	}

	// Выполняем запрос
	resp, err := client.Do(req)
	if err != nil {
		// Определяем тип ошибки для более информативного сообщения
		statusCode := 500
		errorMsg := fmt.Sprintf("Request failed: %v", err)

		if strings.Contains(err.Error(), "timeout") {
			statusCode = 408
			errorMsg = "Request timeout"
		} else if strings.Contains(err.Error(), "no such host") {
			statusCode = 502
			errorMsg = "Host not found"
		} else if strings.Contains(err.Error(), "connection refused") {
			statusCode = 502
			errorMsg = "Connection refused"
		}

		return &ProxyResponse{
			StatusCode: statusCode,
			Error:      errorMsg,
		}
	}
	defer resp.Body.Close()

	// Ограничиваем размер ответа (10MB)
	limitedReader := io.LimitReader(resp.Body, 10*1024*1024)
	respBody, err := io.ReadAll(limitedReader)
	if err != nil {
		return &ProxyResponse{
			StatusCode: resp.StatusCode,
			Error:      fmt.Sprintf("Failed to read response body: %v", err),
		}
	}

	// Собираем заголовки ответа (только безопасные)
	headers := make(map[string]string)
	for key, values := range resp.Header {
		if len(values) > 0 && isSafeResponseHeader(key) {
			headers[key] = values[0]
		}
	}

	return &ProxyResponse{
		StatusCode: resp.StatusCode,
		Headers:    headers,
		Body:       string(respBody),
	}
}

// isSafeHeader проверяет, безопасен ли заголовок для пересылки
func isSafeHeader(header string) bool {
	header = strings.ToLower(header)
	unsafeHeaders := []string{
		"host", "connection", "upgrade", "proxy-connection",
		"proxy-authenticate", "proxy-authorization", "te", "trailers",
		"transfer-encoding",
	}

	for _, unsafe := range unsafeHeaders {
		if header == unsafe {
			return false
		}
	}

	return true
}

// isSafeResponseHeader проверяет, безопасен ли заголовок ответа
func isSafeResponseHeader(header string) bool {
	header = strings.ToLower(header)
	unsafeHeaders := []string{
		"connection", "upgrade", "proxy-connection",
		"proxy-authenticate", "te", "trailers", "transfer-encoding",
		"set-cookie", // Блокируем cookies для безопасности
	}

	for _, unsafe := range unsafeHeaders {
		if header == unsafe {
			return false
		}
	}

	return true
}

// sendErrorResponse отправляет ошибку в формате JSON
func sendErrorResponse(w http.ResponseWriter, statusCode int, message string) {
	w.WriteHeader(statusCode)
	response := ProxyResponse{
		StatusCode: statusCode,
		Error:      message,
	}
	json.NewEncoder(w).Encode(response)
}