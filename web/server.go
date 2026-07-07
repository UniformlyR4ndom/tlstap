package web

import "embed"

//go:embed index.html main.js api.js markers.js layout.js ringbuffer.js format.js transforms.js vendor components transforms/basic.js transforms/numbers.js transforms/compression.js transforms/zip.js
var FS embed.FS
