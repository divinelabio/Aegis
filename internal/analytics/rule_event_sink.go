package analytics

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/divinelab-io/aegis/internal/rules"
	"go.uber.org/zap"
)

const (
	ruleEventQueueCapacity = 4_096
	ruleEventBatchSize     = 128
	ruleEventFlushInterval = 250 * time.Millisecond
	ruleEventWriteTimeout  = 2 * time.Second
	ruleEventRetryLimit    = 3
)

type ruleEventBatchRecorder interface {
	RecordBatch(context.Context, []SecurityEvent) error
}

// RuleEventSinkStats reports the health of the async rule-event delivery path.
// It is intentionally independent from request metrics so delivery failures
// remain observable without delaying security decisions.
type RuleEventSinkStats struct {
	QueueDepth int    `json:"queue_depth"`
	Accepted   uint64 `json:"accepted"`
	Written    uint64 `json:"written"`
	Dropped    uint64 `json:"dropped"`
	Retried    uint64 `json:"retried"`
	Failed     uint64 `json:"failed"`
}

// AsyncRuleEventSink implements rules.EventSink without putting ClickHouse I/O
// on the protected request path. Events are accepted best-effort into a bounded
// queue and written in short, retried batches by one background worker.
type AsyncRuleEventSink struct {
	recorder ruleEventBatchRecorder
	logger   *zap.Logger
	queue    chan SecurityEvent
	done     chan struct{}

	accepted atomic.Uint64
	written  atomic.Uint64
	dropped  atomic.Uint64
	retried  atomic.Uint64
	failed   atomic.Uint64
}

func NewAsyncRuleEventSink(ctx context.Context, store *Store, logger *zap.Logger) *AsyncRuleEventSink {
	if store == nil {
		return nil
	}
	return newAsyncRuleEventSink(ctx, store, logger, ruleEventQueueCapacity)
}

func newAsyncRuleEventSink(ctx context.Context, recorder ruleEventBatchRecorder, logger *zap.Logger, queueCapacity int) *AsyncRuleEventSink {
	if recorder == nil {
		return nil
	}
	if logger == nil {
		logger = zap.NewNop()
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if queueCapacity < 1 {
		queueCapacity = 1
	}
	sink := &AsyncRuleEventSink{
		recorder: recorder,
		logger:   logger,
		queue:    make(chan SecurityEvent, queueCapacity),
		done:     make(chan struct{}),
	}
	go sink.run(ctx)
	return sink
}

// RecordRuleEvent never waits for the analytics database. The request context
// is deliberately not passed to the worker because it is canceled as soon as
// the protected request completes.
func (s *AsyncRuleEventSink) RecordRuleEvent(_ context.Context, event rules.RuleEvent) {
	if s == nil || s.recorder == nil {
		return
	}
	securityEvent := securityEventFromRuleEvent(event)
	select {
	case s.queue <- securityEvent:
		s.accepted.Add(1)
	default:
		s.dropped.Add(1)
		s.logger.Warn("Rule event queue is full; telemetry event dropped")
	}
}

func (s *AsyncRuleEventSink) Stats() RuleEventSinkStats {
	if s == nil {
		return RuleEventSinkStats{}
	}
	return RuleEventSinkStats{
		QueueDepth: len(s.queue),
		Accepted:   s.accepted.Load(),
		Written:    s.written.Load(),
		Dropped:    s.dropped.Load(),
		Retried:    s.retried.Load(),
		Failed:     s.failed.Load(),
	}
}

func (s *AsyncRuleEventSink) run(ctx context.Context) {
	defer close(s.done)
	ticker := time.NewTicker(ruleEventFlushInterval)
	defer ticker.Stop()
	batch := make([]SecurityEvent, 0, ruleEventBatchSize)
	flush := func() {
		if len(batch) == 0 {
			return
		}
		s.writeBatch(batch)
		batch = batch[:0]
	}
	for {
		select {
		case event := <-s.queue:
			batch = append(batch, event)
			if len(batch) >= ruleEventBatchSize {
				flush()
			}
		case <-ticker.C:
			flush()
		case <-ctx.Done():
			flush()
			return
		}
	}
}

func (s *AsyncRuleEventSink) writeBatch(events []SecurityEvent) {
	batch := append([]SecurityEvent(nil), events...)
	for attempt := 0; attempt < ruleEventRetryLimit; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), ruleEventWriteTimeout)
		err := s.recorder.RecordBatch(ctx, batch)
		cancel()
		if err == nil {
			s.written.Add(uint64(len(batch)))
			return
		}
		if attempt+1 < ruleEventRetryLimit {
			s.retried.Add(uint64(len(batch)))
			time.Sleep(time.Duration(attempt+1) * 25 * time.Millisecond)
		}
	}
	s.failed.Add(uint64(len(batch)))
	s.logger.Warn("Rule event batch failed after bounded retries", zap.Int("events", len(batch)))
}
