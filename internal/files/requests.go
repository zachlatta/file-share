package files

import (
	"context"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// FileRequest is one served file: who fetched it and which bytes they got.
// RangeStart is the first byte sent (0 for a whole-file response) and
// BytesSent is how many bytes actually went out, so a player that stops a
// stream early shows a short span.
type FileRequest struct {
	ID         int64     `json:"id"`
	At         time.Time `json:"at"`
	FileID     string    `json:"file_id,omitempty"`
	Namespace  string    `json:"namespace,omitempty"`
	Name       string    `json:"name,omitempty"`
	Version    int       `json:"version,omitempty"`
	Method     string    `json:"method"`
	Status     int       `json:"status"`
	RangeStart int64     `json:"range_start"`
	BytesSent  int64     `json:"bytes_sent"`
	Size       int64     `json:"size"`
	IP         string    `json:"ip,omitempty"`
	Country    string    `json:"country,omitempty"`
	UserAgent  string    `json:"user_agent,omitempty"`
	Referer    string    `json:"referer,omitempty"`
	DurationMS int       `json:"duration_ms"`
}

const requestColumns = `id, at, COALESCE(file_id::text, ''), COALESCE(namespace::text, ''), name, version, method, status,
	range_start, bytes_sent, size, ip, country, user_agent, referer, duration_ms`

// RecordRequest appends a served request to the request log. At defaults to
// now.
func (s *Service) RecordRequest(ctx context.Context, r FileRequest) error {
	if r.At.IsZero() {
		r.At = s.nowUTC()
	}
	_, err := s.db.Exec(ctx, `INSERT INTO file_requests (at, file_id, namespace, name, version, method, status, range_start,
		bytes_sent, size, ip, country, user_agent, referer, duration_ms)
		VALUES ($1, NULLIF($2, '')::uuid, NULLIF($3, '')::uuid, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)`,
		r.At, uuidOrEmpty(r.FileID), uuidOrEmpty(r.Namespace), clip(r.Name, 255), r.Version, clip(r.Method, 8), r.Status,
		r.RangeStart, r.BytesSent, r.Size, clip(r.IP, 64), clip(r.Country, 8), clip(r.UserAgent, 512), clip(r.Referer, 512),
		r.DurationMS)
	return err
}

func clip(v string, n int) string {
	if len(v) > n {
		return v[:n]
	}
	return v
}

type RequestQuery struct {
	FileID    string
	Namespace string
	// Search matches a case-insensitive substring of the IP, user agent or
	// file name.
	Search string
	Since  time.Time
	// Before returns only requests with a smaller ID, for paging.
	Before int64
	Limit  int
}

func (q RequestQuery) where() (string, []any, error) {
	where, args := []string{"true"}, []any{}
	add := func(cond string, v any) {
		args = append(args, v)
		where = append(where, fmt.Sprintf(cond, len(args)))
	}
	for _, c := range []struct{ col, v string }{{"file_id", q.FileID}, {"namespace", q.Namespace}} {
		if c.v == "" {
			continue
		}
		if _, err := uuid.Parse(c.v); err != nil {
			return "", nil, fmt.Errorf("%w: %s must be a UUID", ErrInvalid, c.col)
		}
		add(c.col+" = $%d", c.v)
	}
	if q.Search != "" {
		pattern := "%" + strings.NewReplacer(`\`, `\\`, "%", `\%`, "_", `\_`).Replace(q.Search) + "%"
		add("(ip ILIKE $%[1]d OR user_agent ILIKE $%[1]d OR name ILIKE $%[1]d)", pattern)
	}
	if !q.Since.IsZero() {
		add("at >= $%d", q.Since)
	}
	if q.Before > 0 {
		add("id < $%d", q.Before)
	}
	return strings.Join(where, " AND "), args, nil
}

// ListRequests returns the request log, newest first.
func (s *Service) ListRequests(ctx context.Context, q RequestQuery) ([]FileRequest, error) {
	if q.Limit <= 0 || q.Limit > 1000 {
		q.Limit = 200
	}
	where, args, err := q.where()
	if err != nil {
		return nil, err
	}
	args = append(args, q.Limit)
	rows, err := s.db.Query(ctx, `SELECT `+requestColumns+` FROM file_requests WHERE `+where+
		fmt.Sprintf(` ORDER BY id DESC LIMIT $%d`, len(args)), args...)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, scanRequest)
}

func scanRequest(row pgx.CollectableRow) (FileRequest, error) {
	var r FileRequest
	err := row.Scan(&r.ID, &r.At, &r.FileID, &r.Namespace, &r.Name, &r.Version, &r.Method, &r.Status,
		&r.RangeStart, &r.BytesSent, &r.Size, &r.IP, &r.Country, &r.UserAgent, &r.Referer, &r.DurationMS)
	r.At = r.At.UTC()
	return r, err
}

type ListeningQuery struct {
	FileID    string
	Namespace string
	Since     time.Time
	// Buckets is how many equal slices of the file Coverage has (default
	// 100, so each is 1% of the file).
	Buckets int
}

// FileListening sums up how one file was fetched. A listener is one IP and
// user agent pair. For a constant-bitrate MP3, a fraction of the bytes is the
// same fraction of the running time.
type FileListening struct {
	FileID        string     `json:"file_id"`
	Namespace     string     `json:"namespace"`
	Name          string     `json:"name"`
	Size          int64      `json:"size"`
	Requests      int        `json:"requests"`
	Listeners     int        `json:"listeners"`
	FullDownloads int        `json:"full_downloads"`
	BytesServed   int64      `json:"bytes_served"`
	FirstAt       *time.Time `json:"first_at,omitempty"`
	LastAt        *time.Time `json:"last_at,omitempty"`
	// Coverage[i] is how many listeners received slice i of the file.
	Coverage       []int      `json:"coverage"`
	ListenerDetail []Listener `json:"listeners_detail"`
}

type Listener struct {
	IP          string    `json:"ip"`
	Country     string    `json:"country,omitempty"`
	UserAgent   string    `json:"user_agent"`
	Requests    int       `json:"requests"`
	BytesServed int64     `json:"bytes_served"`
	FirstAt     time.Time `json:"first_at"`
	LastAt      time.Time `json:"last_at"`
	// Covered is the fraction of the file this listener received, and Spans
	// the merged [start, end) fractions.
	Covered float64      `json:"covered"`
	Spans   [][2]float64 `json:"spans"`
}

// Listening reconstructs, per file, which parts were sent to whom.
func (s *Service) Listening(ctx context.Context, q ListeningQuery) ([]FileListening, error) {
	if q.Buckets <= 0 || q.Buckets > 1000 {
		q.Buckets = 100
	}
	where, args, err := RequestQuery{FileID: q.FileID, Namespace: q.Namespace, Since: q.Since}.where()
	if err != nil {
		return nil, err
	}
	rows, err := s.db.Query(ctx, `SELECT `+requestColumns+` FROM file_requests WHERE `+where+` ORDER BY id LIMIT 200000`, args...)
	if err != nil {
		return nil, err
	}
	reqs, err := pgx.CollectRows(rows, scanRequest)
	if err != nil {
		return nil, err
	}
	type span struct{ a, b int64 }
	type listenerAcc struct {
		Listener
		spans []span
	}
	type fileAcc struct {
		FileListening
		listeners map[string]*listenerAcc
		order     []string
	}
	byFile, order := map[string]*fileAcc{}, []string{}
	for _, r := range reqs {
		fa := byFile[r.FileID]
		if fa == nil {
			fa = &fileAcc{FileListening: FileListening{FileID: r.FileID, Namespace: r.Namespace}, listeners: map[string]*listenerAcc{}}
			byFile[r.FileID] = fa
			order = append(order, r.FileID)
		}
		fa.Name, fa.Size = r.Name, r.Size // latest wins
		fa.Requests++
		fa.BytesServed += r.BytesSent
		if r.Method == "GET" && r.Status == 200 && r.Size > 0 && r.BytesSent >= r.Size {
			fa.FullDownloads++
		}
		at := r.At
		if fa.FirstAt == nil {
			fa.FirstAt = &at
		}
		fa.LastAt = &at
		key := r.IP + "\x00" + r.UserAgent
		la := fa.listeners[key]
		if la == nil {
			la = &listenerAcc{Listener: Listener{IP: r.IP, UserAgent: r.UserAgent, FirstAt: at}}
			fa.listeners[key] = la
			fa.order = append(fa.order, key)
		}
		la.Requests++
		la.BytesServed += r.BytesSent
		la.LastAt = at
		if r.Country != "" {
			la.Country = r.Country
		}
		if r.Method == "GET" && r.BytesSent > 0 && (r.Status == 200 || r.Status == 206) {
			la.spans = append(la.spans, span{r.RangeStart, r.RangeStart + r.BytesSent})
		}
	}
	round := func(v float64) float64 { return math.Round(v*10000) / 10000 }
	out := make([]FileListening, 0, len(order))
	for i := len(order) - 1; i >= 0; i-- { // most recently fetched first
		fa := byFile[order[i]]
		fa.Coverage = make([]int, q.Buckets)
		fa.Listeners = len(fa.order)
		fa.ListenerDetail = []Listener{}
		for _, key := range fa.order {
			la := fa.listeners[key]
			sort.Slice(la.spans, func(i, j int) bool { return la.spans[i].a < la.spans[j].a })
			var merged []span
			for _, sp := range la.spans {
				if n := len(merged); n > 0 && sp.a <= merged[n-1].b {
					merged[n-1].b = max(merged[n-1].b, sp.b)
				} else {
					merged = append(merged, sp)
				}
			}
			la.Spans = [][2]float64{}
			var covered int64
			for _, sp := range merged {
				if fa.Size > 0 {
					sp.b = min(sp.b, fa.Size)
					la.Spans = append(la.Spans, [2]float64{round(float64(sp.a) / float64(fa.Size)), round(float64(sp.b) / float64(fa.Size))})
				}
				covered += sp.b - sp.a
			}
			if fa.Size > 0 {
				la.Covered = round(float64(covered) / float64(fa.Size))
				for b := range fa.Coverage {
					mid := (float64(b) + 0.5) * float64(fa.Size) / float64(q.Buckets)
					for _, sp := range merged {
						if float64(sp.a) <= mid && mid < float64(sp.b) {
							fa.Coverage[b]++
							break
						}
					}
				}
			}
			fa.ListenerDetail = append(fa.ListenerDetail, la.Listener)
		}
		out = append(out, fa.FileListening)
	}
	return out, nil
}
