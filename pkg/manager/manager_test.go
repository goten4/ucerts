package manager

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/goten4/ucerts/internal/config"
)

func TestStart(t *testing.T) {
	var loadCount atomic.Int32
	config.Interval = 100 * time.Millisecond
	config.CertificateRequestsPaths = []string{"testdata/requests"}
	mock(t, &LoadCertificateRequests, func() {
		loadCount.Add(1)
	})

	stop := Start()
	time.Sleep(250 * time.Millisecond)
	stop()
	time.Sleep(200 * time.Millisecond)

	assert.Equal(t, int32(3), loadCount.Load())
}
