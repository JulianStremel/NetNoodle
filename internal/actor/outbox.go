package actor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/JulianStremel/netnoodle/internal/orders"
	"github.com/JulianStremel/netnoodle/internal/proto"
)

type resultOutbox struct {
	path    string
	results []proto.OrderResult
}

func openOutbox(path string) (*resultOutbox, error) {
	o := &resultOutbox{path: path, results: []proto.OrderResult{}}
	b, e := os.ReadFile(path)
	if errors.Is(e, os.ErrNotExist) {
		return o, nil
	}
	if e != nil {
		return nil, e
	}
	if e = json.Unmarshal(b, &o.results); e != nil {
		return nil, e
	}
	if o.results == nil {
		return nil, errors.New("invalid result outbox")
	}
	return o, nil
}
func (o *resultOutbox) save(results []proto.OrderResult) error {
	b, e := json.Marshal(results)
	if e != nil {
		return e
	}
	if e = orders.WriteFileDurable(o.path, b); e != nil {
		return e
	}
	o.results = results
	return nil
}
func (o *resultOutbox) contains(id string) bool {
	for _, r := range o.results {
		if r.OrderID == id {
			return true
		}
	}
	return false
}
func (o *resultOutbox) add(r proto.OrderResult) error {
	if o.contains(r.OrderID) {
		return nil
	}
	return o.save(append(append([]proto.OrderResult{}, o.results...), r))
}
func finalResultError(e error) bool {
	// The existing client exposes HTTP statuses as METHOD PATH: STATUS MESSAGE.
	_, tail, ok := strings.Cut(e.Error(), "/v1/orders/result: ")
	if !ok {
		return false
	}
	var status int
	if _, err := fmt.Sscanf(tail, "%d", &status); err != nil {
		return false
	}
	return status >= 400 && status < 500 && status != 408 && status != 429
}
func (o *resultOutbox) flush(ctx context.Context, c Protocol) error {
	for i := 0; i < len(o.results); {
		r := o.results[i]
		e := c.Do(ctx, "POST", "/v1/orders/result", r, nil)
		if e != nil && !finalResultError(e) {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			slog.Warn("send order result; retained in outbox", "order", r.OrderID, "err", e)
			i++
			continue
		}
		next := append([]proto.OrderResult{}, o.results[:i]...)
		next = append(next, o.results[i+1:]...)
		if e = o.save(next); e != nil {
			return e
		}
	}
	return nil
}
