package tls

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLoadCertificateRequests(t *testing.T) {
	var handledFiles []string
	mock(t, &HandleCertificateRequestFile, func(file string) { handledFiles = append(handledFiles, file) })

	LoadCertificateRequests("testdata/requests")

	assert.Equal(t, []string{"testdata/requests/test1.yaml", "testdata/requests/test2.yaml"}, handledFiles)
}
