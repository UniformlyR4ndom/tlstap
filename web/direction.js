// The wire protocol's direction is 0 (client -> server) or 1 (server -> client) everywhere.
export const DIRNUM_C2S = 0
export const DIRNUM_S2C = 1

// The display label each direction is shown as throughout the UI.
export const DIR_C2S = 'C→S'
export const DIR_S2C = 'S→C'

// The CSS class each direction is styled with throughout the UI.
export function dirClass(direction) {
    return direction === DIRNUM_C2S ? 'c2s' : 's2c'
}

export function dirLabel(direction) {
    return direction === DIRNUM_C2S ? DIR_C2S : DIR_S2C
}

// Short machine-readable direction strings for a script's own API boundary (e.g. a
// framer script's chunk.direction) — distinct from DIR_C2S/DIR_S2C above, which are for
// human display.
export const DIRSTR_C2S = 'c2s'
export const DIRSTR_S2C = 's2c'

export function dirToStr(direction) {
    return direction === DIRNUM_C2S ? DIRSTR_C2S : DIRSTR_S2C
}
