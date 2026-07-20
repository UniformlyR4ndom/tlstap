package web

import "embed"

//go:embed index.html main.js api.js tamperApi.js scriptRuntime.js markers.js layout.js ringbuffer.js format.js transforms.js all:vendor components transforms/basic.js transforms/numbers.js transforms/compression.js transforms/zip.js transforms/hash.js transforms/checksum.js transforms/encryption.js transforms/mac.js
var FS embed.FS
