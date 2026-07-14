package web

import "embed"

//go:embed index.html main.js api.js tamperApi.js markers.js layout.js ringbuffer.js format.js transforms.js vendor components transforms/basic.js transforms/numbers.js transforms/compression.js transforms/zip.js transforms/hash.js
var FS embed.FS
