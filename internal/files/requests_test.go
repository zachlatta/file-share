package files

import (
	"context"
	"testing"
	"time"
)

func TestRequestLogAndListening(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	f := h.upload(t, "", "episode.mp3", string(make([]byte, 1000)))
	other := h.upload(t, f.Namespace, "feed.xml", "<rss/>")
	add := func(r FileRequest) {
		t.Helper()
		r.FileID, r.Namespace, r.Name, r.Version, r.Size, r.Method = f.ID, f.Namespace, f.Name, 1, f.Size, "GET"
		if r.Status == 0 {
			r.Status = 206
		}
		if err := h.svc.RecordRequest(ctx, r); err != nil {
			t.Fatal(err)
		}
		h.clock.t = h.clock.t.Add(time.Minute)
	}
	phone := FileRequest{IP: "203.0.113.9", UserAgent: "AppleCoreMedia/1.0", Country: "US"}
	// The phone streams 0-30%, skips ahead, plays 50-60% and replays 10-20%.
	p := phone
	p.RangeStart, p.BytesSent = 0, 300
	add(p)
	p.RangeStart, p.BytesSent = 500, 100
	add(p)
	p.RangeStart, p.BytesSent = 100, 100
	add(p)
	// A second device downloads the whole file.
	add(FileRequest{IP: "198.51.100.7", UserAgent: "Podcasts/4000", Status: 200, BytesSent: 1000})
	// HEAD and 304 requests are logged but carry no audio.
	add(FileRequest{IP: "198.51.100.7", UserAgent: "Podcasts/4000", Status: 304})
	if err := h.svc.RecordRequest(ctx, FileRequest{FileID: other.ID, Namespace: other.Namespace, Name: other.Name, Method: "GET",
		Status: 200, Size: other.Size, BytesSent: other.Size, UserAgent: "Overcast/3.0 (+http://overcast.fm/; 1 subscribers)"}); err != nil {
		t.Fatal(err)
	}

	log, err := h.svc.ListRequests(ctx, RequestQuery{Namespace: f.Namespace})
	if err != nil {
		t.Fatal(err)
	}
	if len(log) != 6 || log[0].Name != "feed.xml" || log[5].RangeStart != 0 || log[5].BytesSent != 300 || log[5].Country != "US" {
		t.Fatalf("log = %+v", log)
	}
	if log, _ := h.svc.ListRequests(ctx, RequestQuery{FileID: f.ID, Search: "overcast"}); len(log) != 0 {
		t.Fatalf("search across files = %+v", log)
	}

	stats, err := h.svc.Listening(ctx, ListeningQuery{Namespace: f.Namespace, Buckets: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(stats) != 2 {
		t.Fatalf("stats = %+v", stats)
	}
	var ep FileListening
	for _, s := range stats {
		if s.FileID == f.ID {
			ep = s
		}
	}
	if ep.Requests != 5 || ep.Listeners != 2 || ep.FullDownloads != 1 || ep.BytesServed != 1500 {
		t.Fatalf("episode totals = %+v", ep)
	}
	want := []int{2, 2, 2, 1, 1, 2, 1, 1, 1, 1}
	for i, n := range want {
		if ep.Coverage[i] != n {
			t.Fatalf("coverage = %v, want %v", ep.Coverage, want)
		}
	}
	var streamer Listener
	for _, l := range ep.ListenerDetail {
		if l.UserAgent == "AppleCoreMedia/1.0" {
			streamer = l
		}
	}
	if streamer.Requests != 3 || streamer.Covered != 0.4 || len(streamer.Spans) != 2 ||
		streamer.Spans[0] != [2]float64{0, 0.3} || streamer.Spans[1] != [2]float64{0.5, 0.6} {
		t.Fatalf("streamer = %+v", streamer)
	}
	// Since filters out older requests.
	stats, _ = h.svc.Listening(ctx, ListeningQuery{FileID: f.ID, Since: h.clock.t.Add(-150 * time.Second)})
	if len(stats) != 1 || stats[0].Requests != 2 || stats[0].Listeners != 1 || len(stats[0].Coverage) != 100 {
		t.Fatalf("since stats = %+v", stats)
	}
}
