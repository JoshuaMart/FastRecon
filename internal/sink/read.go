package sink

import (
	"io"
	"net/http"
)

// maxDrain bounds how much of a webhook response is read before the
// connection is reused. The body is never reported: a webhook target may echo
// the payload, and re-logging it would defeat the redaction applied upstream.
const maxDrain = 4 << 10

func readAndDiscard(resp *http.Response) (int64, error) {
	return io.Copy(io.Discard, io.LimitReader(resp.Body, maxDrain))
}
