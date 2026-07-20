// Logs the SHA256 and Whirlpool digests of every chunk of traffic passing through, in either
// direction, then releases it unmodified — transparent pass-through instrumentation, not
// interception/editing.

tamper.register('onConnect', (conn) => {
    tamper.log(`[connect] #${conn.conn} ${conn.src} -> ${conn.dst}`)
    // A stream only reaches onReceive while it's in intercept mode.
    tamper.setIntercept(conn.conn, true)
})

tamper.register('onClose', (conn) => {
    tamper.log(`[close] #${conn.conn} ${conn.src} -> ${conn.dst}`)
})

// hexEncode(digest) returns bytes, not text — TextDecoder turns the (plain ASCII) hex-with-
// colons output into a loggable string.
function hexDigest(bytes) {
    return new TextDecoder().decode(tamper.transform.basic.hexEncode(bytes, { separator: 'colon' }))
}

tamper.register('onReceive', async (ctx) => {
    const bytes = ctx.get()
    // tamper.transform.* is synchronous from inside a hook — no await needed.
    const sha256Hex = hexDigest(tamper.transform.hash.sha256(bytes))
    const whirlpoolHex = hexDigest(tamper.transform.hash.whirlpool(bytes))
    ctx.log(`(${ctx.direction}) SHA256(${bytes.length} bytes) = ${sha256Hex}`)
    ctx.log(`(${ctx.direction}) Whirlpool(${bytes.length} bytes) = ${whirlpoolHex}`)
    await ctx.release()
})
