import { h, render } from 'preact'
import htm from 'htm'
import App from './components/App.js'

const html = htm.bind(h)
render(html`<${App} />`, document.getElementById('root'))
