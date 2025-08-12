package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/labstack/echo/v4"
)

var (
	clients  = make(map[*websocket.Conn]bool)
	mu       sync.Mutex
	upgrader = websocket.Upgrader{}
)

func handleWS(c echo.Context) error {
	conn, err := upgrader.Upgrade(c.Response(), c.Request(), nil)
	if err != nil {
		return err
	}

	mu.Lock()
	clients[conn] = true
	mu.Unlock()
	log.Println("New client connected")

	stop := make(chan struct{})

	go func() {
		defer func() {
			mu.Lock()
			delete(clients, conn)
			mu.Unlock()
			conn.Close()
			close(stop)
			log.Println("Client disconnected")
		}()

		for {
			_, _, err := conn.ReadMessage()
			if err != nil {
				if websocket.IsCloseError(err, websocket.CloseNormalClosure) || err == io.EOF {
					log.Println("Client closed connection normally")
				} else {
					log.Println("WebSocket read error:", err)
				}
				break
			}
		}
	}()

	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		counter := 0
		for {
			select {
			case <-ticker.C:
				counter++
				msg := fmt.Sprintf("Timer: %d", counter)
				mu.Lock()
				for client := range clients {
					client.WriteMessage(websocket.TextMessage, []byte(msg))
				}
				mu.Unlock()
			case <-stop:
				return
			}
		}
	}()

	return nil
}

func main() {
	e := echo.New()
	e.GET("/ws", handleWS)
	e.GET("/", func(c echo.Context) error {
		return c.String(http.StatusOK, "WebSocket server running")
	})
	e.Logger.Fatal(e.Start(":8080"))
}
