package progress

// noopReporter discards every event. It is the default returned by From when
// no Reporter has been attached to the context.
type noopReporter struct{}

func (noopReporter) Stage(string)        {}
func (noopReporter) Step(string, ...any) {}
func (noopReporter) Progress(int, int)   {}
func (noopReporter) Warn(string, ...any) {}
func (noopReporter) Done(string, ...any) {}

// Discard returns a Reporter that drops all events.
func Discard() Reporter { return noopReporter{} }
