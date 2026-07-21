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

tamper.register('onReceive', async (ctx) => {
    const bytes = ctx.get()
    if (bytes.length === 0) return
    const sha256Hex = tamper.encode.hex(tamper.transform.hash.sha256(bytes))
    ctx.log(`(${ctx.direction}) SHA256(<data> ${bytes.length} bytes): ${sha256Hex}`)
    await ctx.release(bytes.length)
})
