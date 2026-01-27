package log

import (
	"io"
	"log"
	"os"
)

var (
	verbose bool
	logger  *log.Logger
)

func init() {
	logger = log.New(os.Stdout, "", log.LstdFlags)
}

// SetVerbose enables or disables verbose logging
func SetVerbose(v bool) {
	verbose = v
}

// IsVerbose returns whether verbose logging is enabled
func IsVerbose() bool {
	return verbose
}

// SetOutput sets the output destination for the logger
func SetOutput(w io.Writer) {
	logger.SetOutput(w)
}

// SetMultiOutput sets multiple output destinations
func SetMultiOutput(writers ...io.Writer) {
	logger.SetOutput(io.MultiWriter(writers...))
}

// Printf logs a formatted message
func Printf(format string, v ...interface{}) {
	logger.Printf(format, v...)
}

// Println logs a message with newline
func Println(v ...interface{}) {
	logger.Println(v...)
}

// Fatalf logs a fatal error and exits
func Fatalf(format string, v ...interface{}) {
	logger.Fatalf(format, v...)
}

// Fatal logs a fatal error and exits
func Fatal(v ...interface{}) {
	logger.Fatal(v...)
}

// V logs a verbose message (only shown when verbose mode is enabled)
func V(format string, v ...interface{}) {
	if verbose {
		logger.Printf(format, v...)
	}
}

// Info logs an info message
func Info(format string, v ...interface{}) {
	logger.Printf("[INFO] "+format, v...)
}

// Warn logs a warning message
func Warn(format string, v ...interface{}) {
	logger.Printf("[WARN] "+format, v...)
}

// Error logs an error message
func Error(format string, v ...interface{}) {
	logger.Printf("[ERROR] "+format, v...)
}

// Debug logs a debug message (only in verbose mode)
func Debug(format string, v ...interface{}) {
	if verbose {
		logger.Printf("[DEBUG] "+format, v...)
	}
}
