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

func registerLoginMetrics(appName, prefix string) *loginMetricsNames {
	// Three metrics are exposed:
	// <appName>_<prefix>_jwt_issued_count
	// <appName>_<prefix>_jwt_failed_auth_count
	// <appName>_<prefix>_jwt_internal_error_count

	p := ""
	if len(prefix) == 0 {
		p = ""
	} else {
		p = fmt.Sprintf("_%s", prefix)
	}

	issuedCountName := fmt.Sprintf("%s%s_jwt_issued_count",
		appName, p)
	failedAuthName := fmt.Sprintf("%s%s_jwt_failed_auth_count",
		appName, p)
	internalErrorName := fmt.Sprintf("%s%s_jwt_internal_error_count",
		appName, p)

	jwtIssuedCount := prometheus.NewCounter(prometheus.CounterOpts{
		Name: issuedCountName,
		Help: fmt.Sprintf("Count of JWT token issued, for %s%s.",
			appName, p),
	})

	jwtFailedAuthCount := prometheus.NewCounter(prometheus.CounterOpts{
		Name: failedAuthName,
		Help: fmt.Sprintf("Count of auth failure when requesting JWT token, for %s%s.",
			appName, p),
	})

	jwtInternalErrorCount := prometheus.NewCounter(prometheus.CounterOpts{
		Name: internalErrorName,
		Help: fmt.Sprintf("Count of internal error requesting JWT token, for %s%s.",
			appName, p),
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
