package server

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/JulianStremel/netnoodle/internal/store"
)

const sessionCookie = "nn_session"

type ctxKey int

const userKey ctxKey = 1

// RandomToken returns n random bytes as URL-safe base64.
func RandomToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand never fails on supported platforms
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// HashToken is the stored form of a bearer or session token.
func HashToken(tok string) []byte {
	s := sha256.Sum256([]byte(tok))
	return s[:]
}

// HashPassword hashes a password with bcrypt.
func HashPassword(pw string) ([]byte, error) {
	return bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
}

// EnsureAdmin creates the user "admin" with a random password if no user
// exists. It returns the password, or "" if users exist already.
func EnsureAdmin(ctx context.Context, st store.Users) (string, error) {
	n, err := st.CountUsers(ctx)
	if err != nil || n > 0 {
		return "", err
	}
	pw := RandomToken(15)
	h, err := HashPassword(pw)
	if err != nil {
		return "", err
	}
	if _, err := st.CreateUser(ctx, "admin", h); err != nil {
		return "", err
	}
	return pw, nil
}

// dummyHash makes a failed login for an unknown user cost the same time
// as a wrong password.
var dummyHash, _ = bcrypt.GenerateFromPassword([]byte("dummy-password"), bcrypt.DefaultCost)

func (s *Server) checkLogin(ctx context.Context, name, pw string) (store.User, bool) {
	u, err := s.st.UserByName(ctx, name)
	if err != nil {
		bcrypt.CompareHashAndPassword(dummyHash, []byte(pw))
		return u, false
	}
	return u, bcrypt.CompareHashAndPassword(u.PassHash, []byte(pw)) == nil
}

// userFrom returns the logged-in user of a request, if any.
func userFrom(ctx context.Context) (store.User, bool) {
	u, ok := ctx.Value(userKey).(store.User)
	return u, ok
}

// withUser loads the session user (if any) into the request context.
func (s *Server) withUser(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie(sessionCookie); err == nil && c.Value != "" {
			if u, err := s.st.SessionUser(r.Context(), HashToken(c.Value), time.Now()); err == nil {
				r = r.WithContext(context.WithValue(r.Context(), userKey, u))
			}
		}
		next.ServeHTTP(w, r)
	})
}

// requireUser rejects requests without a valid session.
func requireUser(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := userFrom(r.Context()); !ok {
			writeErr(w, http.StatusUnauthorized, "login required")
			return
		}
		next(w, r)
	}
}

// loginLimiter slows down password guessing: at most maxFails failed logins
// per client IP per window.
type loginLimiter struct {
	mu       sync.Mutex
	fails    map[string][]time.Time
	window   time.Duration
	maxFails int
}

func newLoginLimiter() *loginLimiter {
	return &loginLimiter{fails: map[string][]time.Time{}, window: 5 * time.Minute, maxFails: 10}
}

func clientIP(r *http.Request) string {
	h, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return h
}

func (l *loginLimiter) prune(ip string, now time.Time) []time.Time {
	ts := l.fails[ip]
	i := 0
	for i < len(ts) && now.Sub(ts[i]) > l.window {
		i++
	}
	ts = ts[i:]
	if len(ts) == 0 {
		delete(l.fails, ip)
	} else {
		l.fails[ip] = ts
	}
	return ts
}

// maxTrackedIPs bounds the limiter's memory (for example with rotating
// IPv6 addresses). When it is reached, old entries are dropped.
const maxTrackedIPs = 100000

// reserve counts one attempt for ip before the check runs. It returns false
// if the limit is reached. Call release after a successful attempt.
func (l *loginLimiter) reserve(ip string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	ts := l.prune(ip, now)
	if len(ts) >= l.maxFails {
		return false
	}
	if len(l.fails) >= maxTrackedIPs {
		for k := range l.fails {
			l.prune(k, now)
		}
		if len(l.fails) >= maxTrackedIPs {
			l.fails = map[string][]time.Time{}
		}
	}
	l.fails[ip] = append(ts, now)
	return true
}

// release removes the last reserved attempt of ip (it succeeded).
func (l *loginLimiter) release(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if ts := l.fails[ip]; len(ts) > 0 {
		if len(ts) == 1 {
			delete(l.fails, ip)
		} else {
			l.fails[ip] = ts[:len(ts)-1]
		}
	}
}

// rateLimiter allows n events per window and key.
type rateLimiter struct {
	mu     sync.Mutex
	n      int
	window time.Duration
	hits   map[string][]time.Time
}

func newRateLimiter(n int, window time.Duration) *rateLimiter {
	return &rateLimiter{n: n, window: window, hits: map[string][]time.Time{}}
}

func (l *rateLimiter) allow(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.hits) > maxTrackedIPs {
		// Drop keys without recent hits (for example removed peers).
		for k, ts := range l.hits {
			if len(ts) == 0 || now.Sub(ts[len(ts)-1]) > l.window {
				delete(l.hits, k)
			}
		}
	}
	ts := l.hits[key]
	i := 0
	for i < len(ts) && now.Sub(ts[i]) > l.window {
		i++
	}
	ts = ts[i:]
	if len(ts) >= l.n {
		l.hits[key] = ts
		return false
	}
	l.hits[key] = append(ts, now)
	return true
}

var errBadLogin = errors.New("wrong user name or password")
