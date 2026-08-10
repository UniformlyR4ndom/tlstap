import { h } from 'preact'
import htm from 'htm'
import { listDissectScripts, getDissectScript, putDissectScript, deleteDissectScript } from '../dbdumpDissectApi.js'
import { OPERATIONS_BY_CATEGORY } from '../transforms.js'
import { NUMBER_TYPES } from '../transforms/numbers.js'
import { camelCaseOpId, capitalizeTypeId } from '../transformWorkerApi.js'
import ScriptsCrudPanel from './ScriptsCrudPanel.js'

const html = htm.bind(h)

// Reflection-only mirror of the real self.dissector API (dissectRuntime.js), for
// scopeCompletionSource to read property names/types off of — never called. Same
// generation as FramerScriptsPanel.js's FRAMER_COMPLETION_SHAPE, minus `log` (dissector
// scripts have no equivalent) — a new transform op or number type appears here without a
// separate update.
const DISSECTOR_COMPLETION_SHAPE = {
    transform: Object.fromEntries(Object.entries(OPERATIONS_BY_CATEGORY).map(([category, ops]) =>
        [category, Object.fromEntries(Object.keys(ops).map(opId => [camelCaseOpId(opId), () => {}]))])),
    encode: { hex: () => {}, base64: () => {}, hexdump: () => {} },
    decode: { hex: () => {}, base64: () => {}, hexdump: () => {} },
    number: Object.fromEntries(NUMBER_TYPES.flatMap(t => {
        const suffix = capitalizeTypeId(t.id)
        return [[`decode${suffix}`, () => {}], [`encode${suffix}`, () => {}]]
    })),
}

const COMPLETIONS = { dissector: DISSECTOR_COMPLETION_SHAPE }

// "Dissect" bottom-panel tab of the Analysis view: CRUD over dbdump's dissector script
// store via ScriptsCrudPanel.js's generic chrome. CRUD only, no Run/Stop and no Log tab —
// a dissector script runs on-demand per selected frame from TrafficView.js's own
// DissectPanel.js, and errors surface there directly rather than through a running log
// (there's no long-running process to log from, unlike the framer's Run).
export default function DissectScriptsPanel({ refreshSignal }) {
    return html`
        <${ScriptsCrudPanel}
            className="dissect-scripts-view"
            list=${listDissectScripts} get=${getDissectScript} put=${putDissectScript} del=${deleteDissectScript}
            completions=${COMPLETIONS}
            refreshSignal=${refreshSignal}
            listWidthKey="dissectScriptsListWidth"
        />
    `
}
