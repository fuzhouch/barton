package barton

import (
	"fmt"

	"github.com/prometheus/client_golang/prometheus"
)

var globalMetrics map[string]prometheus.Collector

func init() {
	globalMetrics = make(map[string]prometheus.Collector)
}

type loginMetricsNames struct {
	jwtIssuedCount        prometheus.Counter
	jwtFailedAuthCount    prometheus.Counter
	jwtInternalErrorCount prometheus.Counter
}

func registerLoginMetrics(prefix string) *loginMetricsNames {
	// Three metrics are exposed:
	// <prefix>_jwt_issued_count
	// <prefix>_jwt_failed_auth_count
	// <prefix>_jwt_internal_error_count

	issuedCountName := fmt.Sprintf("%s_jwt_issued_count", prefix)
	failedAuthName := fmt.Sprintf("%s_jwt_failed_auth_count", prefix)
	internalErrorName := fmt.Sprintf("%s_jwt_internal_error_count", prefix)

	jwtIssuedCount := prometheus.NewCounter(prometheus.CounterOpts{
		Name: issuedCountName,
		Help: fmt.Sprintf("Count of JWT token issued, for %s.",
			prefix),
	})

	jwtFailedAuthCount := prometheus.NewCounter(prometheus.CounterOpts{
		Name: failedAuthName,
		Help: fmt.Sprintf("Count of auth failure when requesting JWT token, for %s.",
			prefix),
	})

	jwtInternalErrorCount := prometheus.NewCounter(prometheus.CounterOpts{
		Name: internalErrorName,
		Help: fmt.Sprintf("Count of internal error requesting JWT token, for %s.",
			prefix),
	})

	// A counter with duplicated names will break here.
	prometheus.MustRegister(jwtIssuedCount)
	prometheus.MustRegister(jwtFailedAuthCount)
	prometheus.MustRegister(jwtInternalErrorCount)

	globalMetrics[issuedCountName] = jwtIssuedCount
	globalMetrics[failedAuthName] = jwtFailedAuthCount
	globalMetrics[internalErrorName] = jwtInternalErrorCount

	return &loginMetricsNames{
		jwtIssuedCount:        jwtIssuedCount,
		jwtFailedAuthCount:    jwtFailedAuthCount,
		jwtInternalErrorCount: jwtInternalErrorCount,
	}
}

// globalCleanup is an internal function to perform cleanup when program
// exits. It's usually called with Echo's cleanup function.
func globalCleanup() {
	for _, v := range globalMetrics {
		prometheus.Unregister(v)
	}
	globalMetrics = make(map[string]prometheus.Collector)
}
