import { h } from 'preact'
import htm from 'htm'
import { listFramerScripts, getFramerScript, putFramerScript, deleteFramerScript } from '../dbdumpFramerApi.js'
import { OPERATIONS_BY_CATEGORY } from '../transforms.js'
import { NUMBER_TYPES } from '../transforms/numbers.js'
import { camelCaseOpId, capitalizeTypeId } from '../transformWorkerApi.js'
import ScriptsCrudPanel from './ScriptsCrudPanel.js'

const html = htm.bind(h)

// Reflection-only mirror of the real self.framer API (frameRuntime.js), for
// scopeCompletionSource to read property names/types off of — never called. transform's
// shape is generated from OPERATIONS_BY_CATEGORY/camelCaseOpId, number's from
// NUMBER_TYPES/capitalizeTypeId — same inputs TamperScriptsPanel.js's
// TAMPER_COMPLETION_SHAPE uses, so a new transform op or number type appears here
// without a separate update. No fs/RPC methods and no second ctx-like namespace — a
// framer script has neither.
const FRAMER_COMPLETION_SHAPE = {
    transform: Object.fromEntries(Object.entries(OPERATIONS_BY_CATEGORY).map(([category, ops]) =>
        [category, Object.fromEntries(Object.keys(ops).map(opId => [camelCaseOpId(opId), () => {}]))])),
    encode: { hex: () => {}, base64: () => {}, hexdump: () => {} },
    decode: { hex: () => {}, base64: () => {}, hexdump: () => {} },
    number: Object.fromEntries(NUMBER_TYPES.flatMap(t => {
        const suffix = capitalizeTypeId(t.id)
        return [[`decode${suffix}`, () => {}], [`encode${suffix}`, () => {}]]
    })),
    log: () => {},
}

const COMPLETIONS = { framer: FRAMER_COMPLETION_SHAPE }

// "Scripts" bottom-panel tab of the Analysis view: CRUD over dbdump's framer script
// store via ScriptsCrudPanel.js's generic chrome. CRUD only, no Run/Stop — a framer
// script is run against a specific stream from TrafficView.js's own meta-bar "Run"
// button, not from here; see the "Log" tab (FramerLogPanel.js) for that run's output.
export default function FramerScriptsPanel({ refreshSignal }) {
    return html`
        <${ScriptsCrudPanel}
            className="framer-scripts-view"
            list=${listFramerScripts} get=${getFramerScript} put=${putFramerScript} del=${deleteFramerScript}
            completions=${COMPLETIONS}
            refreshSignal=${refreshSignal}
            listWidthKey="framerScriptsListWidth"
        />
    `
}
