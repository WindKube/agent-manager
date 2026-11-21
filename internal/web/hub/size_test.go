package hub

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestHumanSize(t *testing.T) {
	for bytes, want := range map[int64]string{
		0:                     "",
		-1:                    "",
		512:                   "512 B",
		1024:                  "1.0 KB",
		18842:                 "18.4 KB",
		5 * 1024 * 1024:       "5.0 MB",
		1288490189:            "1.2 GB",
		2576980378:            "2.4 GB",
		3 * 1024 * 1024 << 20: "3.0 TB",
		5000 * 1024 << 30:     "5000.0 TB",
	} {
		require.Equalf(t, want, humanSize(bytes), "%d bytes", bytes)
	}
}
