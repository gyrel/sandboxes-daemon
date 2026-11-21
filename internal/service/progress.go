package service

// CreateProgressSnapshot is the transient, advisory pull progress of an
// in-flight create. It lives only for the duration of the blocking Create
// RPC: it is never persisted, it is cleared when the create returns (success
// or abort), and a restarted daemon simply has none. Consumers use it for
// display only; lifecycle keys off sandbox state and operation state.
type CreateProgressSnapshot struct {
	Phase     string
	Completed int64
	Total     int64
}

// setCreateProgress records or replaces the snapshot for one sandbox id.
func (s *Service) setCreateProgress(id string, snapshot CreateProgressSnapshot) {
	s.createProgressMu.Lock()
	defer s.createProgressMu.Unlock()
	if s.createProgress == nil {
		s.createProgress = make(map[string]CreateProgressSnapshot)
	}
	s.createProgress[id] = snapshot
}

// clearCreateProgress drops the snapshot once a create terminates.
func (s *Service) clearCreateProgress(id string) {
	s.createProgressMu.Lock()
	defer s.createProgressMu.Unlock()
	delete(s.createProgress, id)
}

// CreateProgress returns the current transient snapshot for a sandbox id.
// The server layer uses it to decorate Watch events; callers must treat the
// data as best-effort display input.
func (s *Service) CreateProgress(id string) (CreateProgressSnapshot, bool) {
	s.createProgressMu.Lock()
	defer s.createProgressMu.Unlock()
	snapshot, ok := s.createProgress[id]
	return snapshot, ok
}
