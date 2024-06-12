package node

import (
	"context"
	"fmt"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/gorilla/mux"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
)

type explorerServer struct {
	log      log.Logger
	timeouts rpc.HTTPTimeouts
	mux      http.ServeMux // registered handlers go here

	mu       sync.Mutex
	server   *http.Server
	listener net.Listener // non-nil when server is running

	// HTTP RPC handler things.
	httpConfig  httpConfig
	httpHandler atomic.Value // *rpcHandler

	// These are set by setListenAddr.
	endpoint string
	host     string
	port     int

	handlerNames map[string]string
}

func newExplorerServer(log log.Logger, timeouts rpc.HTTPTimeouts) *explorerServer {
	h := &explorerServer{log: log, timeouts: timeouts, handlerNames: make(map[string]string)}
	h.httpHandler.Store((*rpcHandler)(nil))
	return h
}

// setListenAddr configures the listening address of the server.
// The address can only be set while the server isn't running.
func (h *explorerServer) setListenAddr(host string, port int) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.listener != nil && (host != h.host || port != h.port) {
		return fmt.Errorf("explorer server already running on %s", h.endpoint)
	}

	h.host, h.port = host, port
	h.endpoint = net.JoinHostPort(host, fmt.Sprintf("%d", port))
	return nil
}

// listenAddr returns the listening address of the server.
func (h *explorerServer) listenAddr() string {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.listener != nil {
		return h.listener.Addr().String()
	}
	return h.endpoint
}

// InfoHandler 处理 /info 请求
func InfoHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Server is alive!"))
}

// start starts the HTTP server if it is enabled and not already running.
func (h *explorerServer) start() error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.endpoint == "" || h.listener != nil {
		return nil // already running or not configured
	}

	// 创建一个新的 mux 路由器
	router := mux.NewRouter()

	// 注册 /info 路径和处理器
	router.HandleFunc("/info", InfoHandler).Methods("GET")

	// Initialize the server.
	h.server = &http.Server{Handler: router}
	if h.timeouts != (rpc.HTTPTimeouts{}) {
		CheckTimeouts(&h.timeouts)
		h.server.ReadTimeout = h.timeouts.ReadTimeout
		h.server.ReadHeaderTimeout = h.timeouts.ReadHeaderTimeout
		h.server.WriteTimeout = h.timeouts.WriteTimeout
		h.server.IdleTimeout = h.timeouts.IdleTimeout
	}

	// Start the server.
	listener, err := net.Listen("tcp", h.endpoint)
	if err != nil {
		// If the server fails to start, we need to clear out the RPC and WS
		// configuration so they can be configured another time.
		h.disableRPC()
		return err
	}
	h.listener = listener
	go h.server.Serve(listener)

	// if server is websocket only, return after logging
	if !h.rpcAllowed() {
		return nil
	}
	// Log http endpoint.
	h.log.Info("HTTP server started",
		"endpoint", listener.Addr(), "auth", (h.httpConfig.jwtSecret != nil),
		"prefix", h.httpConfig.prefix,
		"cors", strings.Join(h.httpConfig.CorsAllowedOrigins, ","),
		"vhosts", strings.Join(h.httpConfig.Vhosts, ","),
	)

	// Log all handlers mounted on server.
	var paths []string
	for path := range h.handlerNames {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	logged := make(map[string]bool, len(paths))
	for _, path := range paths {
		name := h.handlerNames[path]
		if !logged[name] {
			log.Info(name+" enabled", "url", "http://"+listener.Addr().String()+path)
			logged[name] = true
		}
	}
	return nil
}

func (h *explorerServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Info("********* explorerServer ServeHTTP", "request", r)

	// if http-rpc is enabled, try to serve request
	rpc := h.httpHandler.Load().(*rpcHandler)
	if rpc != nil {
		// First try to route in the mux.
		// Requests to a path below root are handled by the mux,
		// which has all the handlers registered via Node.RegisterHandler.
		// These are made available when RPC is enabled.
		muxHandler, pattern := h.mux.Handler(r)
		if pattern != "" {
			muxHandler.ServeHTTP(w, r)
			return
		}

		if checkPath(r, h.httpConfig.prefix) {
			rpc.ServeHTTP(w, r)
			return
		}
	}
	w.WriteHeader(http.StatusNotFound)
}

// stop shuts down the HTTP server.
func (h *explorerServer) stop() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.doStop()
}

func (h *explorerServer) doStop() {
	if h.listener == nil {
		return // not running
	}

	// Shut down the server.
	httpHandler := h.httpHandler.Load().(*rpcHandler)
	if httpHandler != nil {
		h.httpHandler.Store((*rpcHandler)(nil))
		httpHandler.server.Stop()
	}

	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	err := h.server.Shutdown(ctx)
	if err != nil && err == ctx.Err() {
		h.log.Warn("HTTP server graceful shutdown timed out")
		h.server.Close()
	}

	h.listener.Close()
	h.log.Info("HTTP server stopped", "endpoint", h.listener.Addr())

	// Clear out everything to allow re-configuring it later.
	h.host, h.port, h.endpoint = "", 0, ""
	h.server, h.listener = nil, nil
}

// enableRPC turns on JSON-RPC over HTTP on the server.
func (h *explorerServer) enableRPC(apis []rpc.API, config httpConfig) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.rpcAllowed() {
		return fmt.Errorf("JSON-RPC over HTTP is already enabled")
	}

	// Create RPC server and handler.
	srv := rpc.NewServer()
	srv.SetBatchLimits(config.batchItemLimit, config.batchResponseSizeLimit)
	if err := RegisterApis(apis, config.Modules, srv); err != nil {
		return err
	}
	h.httpConfig = config
	h.httpHandler.Store(&rpcHandler{
		Handler: NewHTTPHandlerStack(srv, config.CorsAllowedOrigins, config.Vhosts, config.jwtSecret),
		server:  srv,
	})
	return nil
}

// disableRPC stops the HTTP RPC handler. This is internal, the caller must hold h.mu.
func (h *explorerServer) disableRPC() bool {
	handler := h.httpHandler.Load().(*rpcHandler)
	if handler != nil {
		h.httpHandler.Store((*rpcHandler)(nil))
		handler.server.Stop()
	}
	return handler != nil
}

// rpcAllowed returns true when JSON-RPC over HTTP is enabled.
func (h *explorerServer) rpcAllowed() bool {
	return h.httpHandler.Load().(*rpcHandler) != nil
}
