package ewpmobile

import (
	"context"
	"fmt"

	"ewp-core/log"

	"github.com/sagernet/sing/common/logger"
)

type ewpLogger struct{}

func (l *ewpLogger) Trace(args ...interface{}) { log.V("%s", fmt.Sprint(args...)) }
func (l *ewpLogger) Debug(args ...interface{}) { log.V("%s", fmt.Sprint(args...)) }
func (l *ewpLogger) Info(args ...interface{})  { log.Printf("%s", fmt.Sprint(args...)) }
func (l *ewpLogger) Warn(args ...interface{})  { log.Printf("%s", fmt.Sprint(args...)) }
func (l *ewpLogger) Error(args ...interface{}) { log.Printf("%s", fmt.Sprint(args...)) }
func (l *ewpLogger) Fatal(args ...interface{}) { log.Printf("%s", fmt.Sprint(args...)) }
func (l *ewpLogger) Panic(args ...interface{}) { log.Printf("%s", fmt.Sprint(args...)) }
func (l *ewpLogger) TraceContext(_ context.Context, args ...interface{}) {
	log.V("%s", fmt.Sprint(args...))
}
func (l *ewpLogger) DebugContext(_ context.Context, args ...interface{}) {
	log.V("%s", fmt.Sprint(args...))
}
func (l *ewpLogger) InfoContext(_ context.Context, args ...interface{}) {
	log.Printf("%s", fmt.Sprint(args...))
}
func (l *ewpLogger) WarnContext(_ context.Context, args ...interface{}) {
	log.Printf("%s", fmt.Sprint(args...))
}
func (l *ewpLogger) ErrorContext(_ context.Context, args ...interface{}) {
	log.Printf("%s", fmt.Sprint(args...))
}
func (l *ewpLogger) FatalContext(_ context.Context, args ...interface{}) {
	log.Printf("%s", fmt.Sprint(args...))
}
func (l *ewpLogger) PanicContext(_ context.Context, args ...interface{}) {
	log.Printf("%s", fmt.Sprint(args...))
}

var _ logger.Logger = (*ewpLogger)(nil)
