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
