package main

import (
	"embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/net/websocket"
)

//go:embed static/*
var staticFiles embed.FS

const (
	BaseDir       = "/opt/horizons"
	VMDir         = BaseDir + "/vm"
	ISODir        = BaseDir + "/iso"
	ConfigFile    = BaseDir + "/config.json"
	QMPSocket     = VMDir + "/qmp.sock"
	VNCSocket     = VMDir + "/vnc.sock"
	MaxISOSize    = 6 * 1024 * 1024 * 1024 // 6GB
	ListenAddr    = "127.0.0.1:8080"
)

type Config struct {
	Username string `json:"username"`
	Password string `json:"password"`
	VMMemory string `json:"vm_memory"`
	VMCPUs   int    `json:"vm_cpus"`
	DiskPath string `json:"disk_path"`
	DiskSize string `json:"disk_size"`
}

type VMState struct {
	Running     bool   `json:"running"`
	ISOAttached bool   `json:"iso_attached"`
	ISOName     string `json:"iso_name"`
}

type Horizons struct {
	config    Config
	state     VMState
	qmpConn   *QMPClient
	mu        sync.RWMutex
	cmd       *exec.Cmd
}

func NewHorizons() (*Horizons, error) {
	h := &Horizons{}
	if err := h.loadConfig(); err != nil {
		return nil, err
	}
	for _, dir := range []string{BaseDir, VMDir, ISODir} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}
	return h, nil
}

func (h *Horizons) loadConfig() error {
	h.config = Config{
		Username: "admin",
		Password: "horizons",
		VMMemory: "2G",
		VMCPUs:   2,
		DiskPath: VMDir + "/disk.qcow2",
		DiskSize: "20G",
	}
	data, err := os.ReadFile(ConfigFile)
	if err != nil {
		if os.IsNotExist(err) {
			return h.saveConfig()
		}
		return err
	}
	return json.Unmarshal(data, &h.config)
}

func (h *Horizons) saveConfig() error {
	data, err := json.MarshalIndent(h.config, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(ConfigFile, data, 0600)
}

func (h *Horizons) basicAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth == "" {
			w.Header().Set("WWW-Authenticate", `Basic realm="Horizons"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		payload, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(auth, "Basic "))
		if err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		pair := strings.SplitN(string(payload), ":", 2)
		if len(pair) != 2 || pair[0] != h.config.Username || pair[1] != h.config.Password {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

func (h *Horizons) startVM() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.state.Running {
		return fmt.Errorf("VM is already running")
	}
	if _, err := os.Stat(h.config.DiskPath); os.IsNotExist(err) {
		cmd := exec.Command("qemu-img", "create", "-f", "qcow2", h.config.DiskPath, h.config.DiskSize)
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("failed to create disk: %s: %w", string(out), err)
		}
	}
	args := []string{
		"-enable-kvm",
		"-m", h.config.VMMemory,
		"-smp", fmt.Sprintf("%d", h.config.VMCPUs),
		"-drive", fmt.Sprintf("file=%s,format=qcow2,if=virtio", h.config.DiskPath),
		"-vnc", "unix:" + VNCSocket,
		"-qmp", "unix:" + QMPSocket + ",server,nowait",
		"-boot", "order=d,menu=on",
		"-device", "virtio-net-pci,netdev=net0",
		"-netdev", "user,id=net0",
		"-usb",
		"-device", "usb-tablet",
	}
	isoPath := h.getCurrentISO()
	if isoPath != "" {
		args = append(args, "-cdrom", isoPath)
		h.state.ISOAttached = true
		h.state.ISOName = filepath.Base(isoPath)
	}
	h.cmd = exec.Command("qemu-system-x86_64", args...)
	h.cmd.Stdout = os.Stdout
	h.cmd.Stderr = os.Stderr
	if err := h.cmd.Start(); err != nil {
		return fmt.Errorf("failed to start VM: %w", err)
	}
	h.state.Running = true
	go h.waitForVM()
	time.Sleep(500 * time.Millisecond)
	if err := h.connectQMP(); err != nil {
		log.Printf("Warning: QMP connection failed: %v", err)
	}
	return nil
}

func (h *Horizons) waitForVM() {
	if h.cmd != nil {
		h.cmd.Wait()
	}
	h.mu.Lock()
	h.state.Running = false
	if h.qmpConn != nil {
		h.qmpConn.Close()
		h.qmpConn = nil
	}
	h.mu.Unlock()
}

func (h *Horizons) connectQMP() error {
	for i := 0; i < 10; i++ {
		qmp, err := NewQMPClient(QMPSocket)
		if err == nil {
			h.qmpConn = qmp
			return nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	return fmt.Errorf("failed to connect to QMP")
}

func (h *Horizons) getCurrentISO() string {
	files, err := os.ReadDir(ISODir)
	if err != nil {
		return ""
	}
	for _, f := range files {
		if strings.HasSuffix(strings.ToLower(f.Name()), ".iso") {
			return filepath.Join(ISODir, f.Name())
		}
	}
	return ""
}

func (h *Horizons) stopVM(force bool) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.state.Running {
		return fmt.Errorf("VM is not running")
	}
	if force {
		if h.cmd != nil && h.cmd.Process != nil {
			return h.cmd.Process.Kill()
		}
		return fmt.Errorf("no process to kill")
	}
	if h.qmpConn != nil {
		return h.qmpConn.Execute("system_powerdown", nil)
	}
	return fmt.Errorf("QMP not connected")
}

func (h *Horizons) rebootVM(force bool) error {
	h.mu.RLock()
	if !h.state.Running {
		h.mu.RUnlock()
		return fmt.Errorf("VM is not running")
	}
	qmp := h.qmpConn
	h.mu.RUnlock()
	if qmp == nil {
		return fmt.Errorf("QMP not connected")
	}
	if force {
		return qmp.Execute("system_reset", nil)
	}
	return qmp.Execute("send-key", map[string]interface{}{
		"keys": []map[string]string{
			{"type": "qcode", "data": "ctrl"},
			{"type": "qcode", "data": "alt"},
			{"type": "qcode", "data": "delete"},
		},
	})
}

func (h *Horizons) uploadISO(r *http.Request) error {
	r.Body = http.MaxBytesReader(nil, r.Body, MaxISOSize)
	file, header, err := r.FormFile("iso")
	if err != nil {
		return fmt.Errorf("failed to get file: %w", err)
	}
	defer file.Close()
	if !strings.HasSuffix(strings.ToLower(header.Filename), ".iso") {
		return fmt.Errorf("file must be an ISO image")
	}
	h.clearISOs()
	dst := filepath.Join(ISODir, header.Filename)
	out, err := os.Create(dst)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer out.Close()
	if _, err := io.Copy(out, file); err != nil {
		os.Remove(dst)
		return fmt.Errorf("failed to save file: %w", err)
	}
	return nil
}

func (h *Horizons) clearISOs() {
	files, _ := os.ReadDir(ISODir)
	for _, f := range files {
		if strings.HasSuffix(strings.ToLower(f.Name()), ".iso") {
			os.Remove(filepath.Join(ISODir, f.Name()))
		}
	}
	h.mu.Lock()
	h.state.ISOAttached = false
	h.state.ISOName = ""
	h.mu.Unlock()
}

func (h *Horizons) detachISO() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.qmpConn != nil && h.state.Running {
		h.qmpConn.Execute("eject", map[string]interface{}{
			"device": "ide1-cd0",
			"force":  true,
		})
	}
	h.state.ISOAttached = false
	h.state.ISOName = ""
	files, _ := os.ReadDir(ISODir)
	for _, f := range files {
		if strings.HasSuffix(strings.ToLower(f.Name()), ".iso") {
			os.Remove(filepath.Join(ISODir, f.Name()))
		}
	}
	return nil
}

func (h *Horizons) handleAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	path := strings.TrimPrefix(r.URL.Path, "/api/")
	var resp interface{}
	var err error
	switch {
	case path == "status" && r.Method == "GET":
		h.mu.RLock()
		resp = h.state
		h.mu.RUnlock()
	case path == "start" && r.Method == "POST":
		err = h.startVM()
		resp = map[string]string{"status": "started"}
	case path == "stop" && r.Method == "POST":
		force := r.URL.Query().Get("force") == "true"
		err = h.stopVM(force)
		resp = map[string]string{"status": "stopping"}
	case path == "reboot" && r.Method == "POST":
		force := r.URL.Query().Get("force") == "true"
		err = h.rebootVM(force)
		resp = map[string]string{"status": "rebooting"}
	case path == "iso/upload" && r.Method == "POST":
		err = h.uploadISO(r)
		resp = map[string]string{"status": "uploaded"}
	case path == "iso/detach" && r.Method == "POST":
		err = h.detachISO()
		resp = map[string]string{"status": "detached"}
	default:
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	json.NewEncoder(w).Encode(resp)
}

func (h *Horizons) handleVNCWebSocket(ws *websocket.Conn) {
	vncConn, err := NewVNCProxy(VNCSocket)
	if err != nil {
		log.Printf("VNC proxy error: %v", err)
		return
	}
	defer vncConn.Close()
	ws.PayloadType = websocket.BinaryFrame
	done := make(chan struct{})
	go func() {
		buf := make([]byte, 32*1024)
		for {
			n, err := vncConn.Read(buf)
			if err != nil {
				break
			}
			if _, err := ws.Write(buf[:n]); err != nil {
				break
			}
		}
		close(done)
	}()
	buf := make([]byte, 32*1024)
	for {
		n, err := ws.Read(buf)
		if err != nil {
			break
		}
		if _, err := vncConn.Write(buf[:n]); err != nil {
			break
		}
	}
	<-done
}

func (h *Horizons) setupRoutes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/", h.basicAuth(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" || r.URL.Path == "/index.html" {
			data, _ := staticFiles.ReadFile("static/index.html")
			w.Header().Set("Content-Type", "text/html")
			w.Write(data)
			return
		}
		if r.URL.Path == "/vnc.html" {
			data, _ := staticFiles.ReadFile("static/vnc.html")
			w.Header().Set("Content-Type", "text/html")
			w.Write(data)
			return
		}
		http.FileServer(http.FS(staticFiles)).ServeHTTP(w, r)
	}))
	mux.HandleFunc("/api/", h.basicAuth(h.handleAPI))
	mux.HandleFunc("/websockify", h.basicAuth(func(w http.ResponseWriter, r *http.Request) {
		websocket.Handler(h.handleVNCWebSocket).ServeHTTP(w, r)
	}))
	return mux
}

func main() {
	h, err := NewHorizons()
	if err != nil {
		log.Fatalf("Failed to initialize Horizons: %v", err)
	}
	srv := &http.Server{
		Addr:         ListenAddr,
		Handler:      h.setupRoutes(),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}
	go func() {
		log.Printf("Horizons starting on %s", ListenAddr)
		if err := srv.ListenAndServe(); err != http.ErrServerClosed {
			log.Fatalf("Server error: %v", err)
		}
	}()
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("Shutting down...")
	h.stopVM(true)
	srv.Close()
}