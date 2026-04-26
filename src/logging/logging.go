package logging

import (
"fmt"
"io"
"log"
"os"
"path/filepath"
"time"
)

type Logger struct {
Access   *log.Logger
Server   *log.Logger
Error    *log.Logger
Audit    *log.Logger
Security *log.Logger
logDir   string
}

func New(logDir string) (*Logger, error) {
if err := os.MkdirAll(logDir, 0755); err != nil {
return nil, fmt.Errorf("creating log directory: %w", err)
}

accessFile, err := openLogFile(filepath.Join(logDir, "access.log"))
if err != nil {
return nil, err
}

serverFile, err := openLogFile(filepath.Join(logDir, "server.log"))
if err != nil {
return nil, err
}

errorFile, err := openLogFile(filepath.Join(logDir, "error.log"))
if err != nil {
return nil, err
}

auditFile, err := openLogFile(filepath.Join(logDir, "audit.log"))
if err != nil {
return nil, err
}

securityFile, err := openLogFile(filepath.Join(logDir, "security.log"))
if err != nil {
return nil, err
}

return &Logger{
Access:   log.New(io.MultiWriter(accessFile, os.Stdout), "[ACCESS] ", log.LstdFlags),
Server:   log.New(io.MultiWriter(serverFile, os.Stdout), "[SERVER] ", log.LstdFlags),
Error:    log.New(io.MultiWriter(errorFile, os.Stderr), "[ERROR] ", log.LstdFlags),
Audit:    log.New(auditFile, "", 0),
Security: log.New(io.MultiWriter(securityFile, os.Stdout), "[SECURITY] ", log.LstdFlags),
logDir:   logDir,
}, nil
}

func openLogFile(path string) (*os.File, error) {
return os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
}

func (l *Logger) AuditLog(event string, data map[string]interface{}) {
entry := map[string]interface{}{
"timestamp": time.Now().UTC().Format(time.RFC3339),
"event":     event,
"data":      data,
}
l.Audit.Printf("%v\n", entry)
}
