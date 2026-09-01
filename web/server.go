package web

import "embed"

//go:embed index.html main.js api.js tamperApi.js tamperFramerApi.js coreApiClient.js scriptRuntime.js transformWorkerApi.js dbdumpFramerApi.js frameRuntime.js hpackDecode.js framerRun.js framerPrefs.js dissectRuntime.js dbdumpDissectApi.js dissectPrefs.js markers.js layout.js useResizableLayout.js useDismissOnOutsideClick.js useChunkBuffer.js useByteBuffer.js byteBufferCore.js chunkSegments.js frameSegments.js frameSegmentsCore.js byteRangesCore.js usePoll.js format.js download.js direction.js transforms.js all:vendor components transforms/basic.js transforms/numbers.js transforms/compression.js transforms/zip.js transforms/hash.js transforms/checksum.js transforms/encryption.js transforms/mac.js
var FS embed.FS
