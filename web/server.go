package web

import "embed"

//go:embed index.html main.js api.js markers.js layout.js ringbuffer.js format.js transforms.js vendor components
var FS embed.FS
