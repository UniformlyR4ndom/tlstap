import { RingBuffer } from '../web/ringbuffer.js'

let passed = 0, failed = 0

function assert(cond, msg) {
    if (cond) { console.log(`  ✓ ${msg}`); passed++ }
    else       { console.error(`  ✗ ${msg}`); failed++ }
}
function eq(a, b, msg) { assert(a === b, `${msg} — got ${JSON.stringify(a)}, want ${JSON.stringify(b)}`) }
function throws(fn, msg) {
    try { fn(); assert(false, `${msg} — expected throw, got none`) }
    catch { assert(true, msg) }
}

// ── basic pushBack ────────────────────────────────────────────────────────────
console.log('\npushBack + get')
{
    const rb = new RingBuffer(4)
    rb.pushBack(1); rb.pushBack(2); rb.pushBack(3)
    eq(rb.length, 3, 'length')
    eq(rb.get(0), 1, 'get(0)')
    eq(rb.get(1), 2, 'get(1)')
    eq(rb.get(2), 3, 'get(2)')
}

// ── basic pushFront ───────────────────────────────────────────────────────────
console.log('\npushFront + get')
{
    const rb = new RingBuffer(4)
    rb.pushFront(3); rb.pushFront(2); rb.pushFront(1)
    eq(rb.length, 3, 'length')
    eq(rb.get(0), 1, 'get(0)')
    eq(rb.get(1), 2, 'get(1)')
    eq(rb.get(2), 3, 'get(2)')
}

// ── evictFront ────────────────────────────────────────────────────────────────
console.log('\nevictFront')
{
    const rb = new RingBuffer(4)
    rb.pushBack(1); rb.pushBack(2); rb.pushBack(3)
    rb.evictFront()
    eq(rb.length, 2, 'length after evict')
    eq(rb.get(0), 2, 'get(0)')
    eq(rb.get(1), 3, 'get(1)')
}

// ── evictBack ─────────────────────────────────────────────────────────────────
console.log('\nevictBack')
{
    const rb = new RingBuffer(4)
    rb.pushBack(1); rb.pushBack(2); rb.pushBack(3)
    rb.evictBack()
    eq(rb.length, 2, 'length after evict')
    eq(rb.get(0), 1, 'get(0)')
    eq(rb.get(1), 2, 'get(1)')
}

// ── wrap-around (pushBack side) ───────────────────────────────────────────────
console.log('\nwrap-around — pushBack side')
{
    const rb = new RingBuffer(4)
    rb.pushBack(1); rb.pushBack(2); rb.pushBack(3); rb.pushBack(4)
    rb.evictFront(); rb.evictFront()
    rb.pushBack(5); rb.pushBack(6)
    eq(rb.length, 4, 'length')
    eq(rb.get(0), 3, 'get(0)'); eq(rb.get(1), 4, 'get(1)')
    eq(rb.get(2), 5, 'get(2)'); eq(rb.get(3), 6, 'get(3)')
}

// ── wrap-around (pushFront side) ──────────────────────────────────────────────
console.log('\nwrap-around — pushFront side')
{
    const rb = new RingBuffer(4)
    rb.pushBack(3); rb.pushBack(4)
    rb.pushFront(2); rb.pushFront(1)
    rb.evictBack(); rb.evictBack()
    rb.pushFront(0)
    eq(rb.length, 3, 'length')
    eq(rb.get(0), 0, 'get(0)'); eq(rb.get(1), 1, 'get(1)'); eq(rb.get(2), 2, 'get(2)')
}

// ── growth via pushBack ───────────────────────────────────────────────────────
console.log('\ngrowth via pushBack')
{
    const rb = new RingBuffer(4)
    for (let i = 0; i < 20; i++) rb.pushBack(i)
    eq(rb.length, 20, 'length')
    for (let i = 0; i < 20; i++) eq(rb.get(i), i, `get(${i})`)
}

// ── growth via pushFront ──────────────────────────────────────────────────────
console.log('\ngrowth via pushFront')
{
    const rb = new RingBuffer(4)
    for (let i = 19; i >= 0; i--) rb.pushFront(i)
    eq(rb.length, 20, 'length')
    for (let i = 0; i < 20; i++) eq(rb.get(i), i, `get(${i})`)
}

// ── mixed pushFront/pushBack with growth ──────────────────────────────────────
console.log('\nmixed pushFront/pushBack with growth')
{
    const rb = new RingBuffer(4)
    rb.pushBack(3); rb.pushBack(4); rb.pushBack(5)
    rb.pushFront(2); rb.pushFront(1)   // triggers growth mid-sequence
    eq(rb.length, 5, 'length')
    for (let i = 0; i < 5; i++) eq(rb.get(i), i + 1, `get(${i})`)
}

// ── growth when buffer wraps across array boundary ────────────────────────────
console.log('\ngrowth while wrapped')
{
    const rb = new RingBuffer(4)
    // Fill, evict 2 from front, push 2 back — tail wraps around
    for (let i = 0; i < 4; i++) rb.pushBack(i)
    rb.evictFront(); rb.evictFront()
    rb.pushBack(4); rb.pushBack(5)  // now wrapped: [4,5,2,3], head=2, tail=6
    // Now push 3 more to force growth
    rb.pushBack(6); rb.pushBack(7); rb.pushBack(8)
    eq(rb.length, 7, 'length')
    for (let i = 0; i < 7; i++) eq(rb.get(i), i + 2, `get(${i})`)
}

// ── errors on empty buffer ────────────────────────────────────────────────────
console.log('\nerrors on empty buffer')
{
    const rb = new RingBuffer(4)
    throws(() => rb.evictFront(), 'evictFront on empty throws')
    throws(() => rb.evictBack(),  'evictBack on empty throws')
    rb.pushBack(1); rb.evictFront()
    throws(() => rb.evictFront(), 'evictFront after drain throws')
    throws(() => rb.evictBack(),  'evictBack after drain throws')
}

// ── evicted slots are cleared (GC friendliness) ───────────────────────────────
console.log('\nevicted slots are cleared')
{
    const rb = new RingBuffer(4)
    rb.pushBack({ x: 1 })
    const slot = rb._head & rb._mask
    rb.evictFront()
    eq(rb._buf[slot], undefined, 'front slot cleared')

    rb.pushBack({ x: 2 })
    rb.pushBack({ x: 3 })
    const backSlot = (rb._tail - 1) & rb._mask
    rb.evictBack()
    eq(rb._buf[backSlot], undefined, 'back slot cleared')
}

// ── summary ───────────────────────────────────────────────────────────────────
console.log(`\n${passed} passed, ${failed} failed`)
if (failed > 0) process.exit(1)
