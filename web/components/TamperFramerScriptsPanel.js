import { h } from 'preact'
import htm from 'htm'
import { OPERATIONS_BY_CATEGORY } from '../transforms.js'
import { NUMBER_TYPES } from '../transforms/numbers.js'
import { camelCaseOpId, capitalizeTypeId } from '../transformWorkerApi.js'
import ScriptsCrudPanel from './ScriptsCrudPanel.js'

const html = htm.bind(h)

// Reflection-only mirror of the real self.framer API a tamper framer script runs against
// (scriptRuntime.js's BOOTSTRAP), for scopeCompletionSource to read property names/types
// off of — never called. transform's/number's shapes are generated the same way
// TamperScriptsPanel.js's/dbdump's FramerScriptsPanel.js's own completion shapes are.
// Unlike dbdump's framer scripts, tamper's also get fs/kv (see doc/design/
// tamper-framer.md) but no RPC/ctx-like namespace — a framer script has neither.
const TAMPER_FRAMER_COMPLETION_SHAPE = {
    transform: Object.fromEntries(Object.entries(OPERATIONS_BY_CATEGORY).map(([category, ops]) =>
        [category, Object.fromEntries(Object.keys(ops).map(opId => [camelCaseOpId(opId), () => {}]))])),
    encode: { hex: () => {}, base64: () => {}, hexdump: () => {} },
    decode: { hex: () => {}, base64: () => {}, hexdump: () => {} },
    number: Object.fromEntries(NUMBER_TYPES.flatMap(t => {
        const suffix = capitalizeTypeId(t.id)
        return [[`decode${suffix}`, () => {}], [`encode${suffix}`, () => {}]]
    })),
    fs: {
        listFiles: () => {},
        readFile: () => {},
        writeFile: () => {},
        appendFile: () => {},
    },
    kv: {
        read: () => {},
        write: () => {},
        readBytes: () => {},
        writeBytes: () => {},
        list: () => {},
        delete: () => {},
    },
    log: () => {},
}

const COMPLETIONS = { framer: TAMPER_FRAMER_COMPLETION_SHAPE }

// "Framer Scripts" sub-tab of the Tamper view: CRUD over tamper's own framer-script store
// via ScriptsCrudPanel.js's generic chrome. CRUD only, no Run/Stop — a framer script is
// selected from the Scripts sub-tab's picker (TamperScriptsPanel.js) and runs composed
// with whichever interception script is Run there, not from this panel.
export default function TamperFramerScriptsPanel({ tamperFramerApi, refreshSignal }) {
    return html`
        <${ScriptsCrudPanel}
            className="tamper-framer-scripts-view"
            list=${tamperFramerApi.listFramerScripts} get=${tamperFramerApi.getFramerScript}
            put=${tamperFramerApi.putFramerScript} del=${tamperFramerApi.deleteFramerScript}
            completions=${COMPLETIONS}
            refreshSignal=${refreshSignal}
            listWidthKey="tamperFramerScriptsListWidth"
        />
    `
}
