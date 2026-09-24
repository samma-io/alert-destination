package awsadapt

import "time"

// Times are stored as epoch seconds rather than RFC 3339 strings so that the TTL
// attribute and every other timestamp share one representation, and so nothing
// depends on a marshaller's date format.
func unix(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UTC().Unix()
}

func fromUnix(secs int64) time.Time {
	if secs == 0 {
		return time.Time{}
	}
	return time.Unix(secs, 0).UTC()
}
