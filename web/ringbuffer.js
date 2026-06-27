export class RingBuffer {
    constructor(capacity = 16) {
        const cap = nextPow2(Math.max(capacity, 1))
        this._buf = new Array(cap)
        this._mask = cap - 1
        this._head = 0  // absolute index of first element
        this._tail = 0  // absolute index one past last element
    }

    get length() { return this._tail - this._head }
    get capacity() { return this._mask + 1 }

    get(i) {
        return this._buf[(this._head + i) & this._mask]
    }

    pushBack(item) {
        if (this.length === this.capacity) this._grow()
        this._buf[this._tail & this._mask] = item
        this._tail++
    }

    pushFront(item) {
        if (this.length === this.capacity) this._grow()
        this._head--
        this._buf[this._head & this._mask] = item
    }

    evictFront() {
        if (this.length === 0) throw new RangeError('evictFront on empty RingBuffer')
        this._buf[this._head & this._mask] = undefined  // release reference for GC
        this._head++
    }

    evictBack() {
        if (this.length === 0) throw new RangeError('evictBack on empty RingBuffer')
        this._tail--
        this._buf[this._tail & this._mask] = undefined  // release reference for GC
    }

    _grow() {
        const len = this.length
        const newCap = this.capacity * 2
        const newBuf = new Array(newCap)
        for (let i = 0; i < len; i++)
            newBuf[i] = this._buf[(this._head + i) & this._mask]
        this._buf = newBuf
        this._mask = newCap - 1
        this._head = 0
        this._tail = len
    }
}

function nextPow2(n) {
    return n <= 1 ? 1 : 1 << Math.ceil(Math.log2(n))
}
