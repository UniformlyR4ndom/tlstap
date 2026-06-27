package web

import "embed"

//go:embed index.html main.js api.js ringbuffer.js vendor components
var FS embed.FS
