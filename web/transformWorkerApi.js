// Shared naming between an op id (transforms.js's OPERATIONS_BY_CATEGORY) and the JS
// identifier exposed for it on a Worker-side transform surface (tamper.transform.* in
// scriptRuntime.js, framer.transform.* in frameRuntime.js). Runs on the main thread, at
// Worker-construction time — the actual per-op function body (how the call reaches
// OPERATIONS: synchronously, or Promise-wrapped pending a module import) is supplied by
// the caller via buildTransformApiSource's fnBody, since that differs by runtime.
import { OPERATIONS_BY_CATEGORY } from './transforms.js'
import { NUMBER_TYPES } from './transforms/numbers.js'

// Maps an op id that can't camelCase into a valid identifier (leads with a digit, e.g.
// `3des-encrypt`) or that collides with its own inverse (`xor-encrypt`/`xor-decrypt` is a
// self-inverse repeating-key XOR) to the name actually exposed on the transform surface.
const TRANSFORM_NAME_OVERRIDES = {
    '3des-encrypt': 'tripleDesEncrypt',
    '3des-decrypt': 'tripleDesDecrypt',
    'xor-encrypt': 'xorCrypt',
    'xor-decrypt': 'xorCrypt',
}

// Exported so its output can be mirrored by an autocomplete shape elsewhere.
export function camelCaseOpId(opId) {
    return TRANSFORM_NAME_OVERRIDES[opId] ?? opId.replace(/-([a-z0-9])/g, (_, c) => c.toUpperCase())
}

// Built once per Worker source string (the op catalog is static for the page's lifetime)
// and spliced directly into a BOOTSTRAP template literal; fnBody(opId) renders the actual
// function's source text for one op id. A camelCase collision keeps the first op id and
// skips the rest — safe since a collision only happens between op ids whose run() is the
// same function.
export function buildTransformApiSource(fnBody) {
    const categories = Object.entries(OPERATIONS_BY_CATEGORY).map(([category, ops]) => {
        const seenNames = new Set()
        const fns = []
        for (const opId of Object.keys(ops)) {
            const fnName = camelCaseOpId(opId)
            if (seenNames.has(fnName)) continue
            seenNames.add(fnName)
            fns.push(`${fnName}: ${fnBody(opId)}`)
        }
        return `${category}: { ${fns.join(', ')} }`
    })
    return `{ ${categories.join(', ')} }`
}

// Default params for the no-params encode/decode case: plain contiguous hex/base64,
// matching how a digest is normally printed.
export const HEX_DEFAULTS = { prefix: '', separator: '' }
export const BASE64_DEFAULTS = { urlSafe: false }

// framer.number.*/tamper.number.* — real numbers/bigints, not OPERATIONS' decimal-text
// convention (see transforms/numbers.js's decodeNumberValue/encodeNumberValue). Naming
// mirrors the decnum-*/encnum-* op id split rather than camelCaseOpId above: id 'u32be'
// becomes decodeU32be/encodeU32be.
export function capitalizeTypeId(id) {
    return id.charAt(0).toUpperCase() + id.slice(1)
}

// Built once per Worker source string and spliced into a BOOTSTRAP template literal;
// fnBody(type, kind) renders the source text for one direction ('decode'|'encode') of one
// number type — the type's own shape (bytes/get/set/le/big/label) is inlined as a JSON
// literal by the caller, so the generated function needs no runtime lookup back into
// NUMBER_TYPES.
export function buildNumberApiSource(fnBody) {
    const entries = []
    for (const type of NUMBER_TYPES) {
        const suffix = capitalizeTypeId(type.id)
        entries.push(`decode${suffix}: ${fnBody(type, 'decode')}`)
        entries.push(`encode${suffix}: ${fnBody(type, 'encode')}`)
    }
    return `{ ${entries.join(', ')} }`
}
