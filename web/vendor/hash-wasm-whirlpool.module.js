// Vendored from hash-wasm 4.12.0 (MIT license, https://github.com/Daninet/hash-wasm),
// specifically dist/whirlpool.umd.min.js — a self-contained, dependency-free per-algorithm
// bundle (the WASM binary is inlined as a base64 string; no separate .wasm fetch). crypto-js
// (../vendor/crypto-js.module.js) is used for every hash algorithm it supports; this is only
// for Whirlpool, which crypto-js doesn't have. Kept as-is (upstream ships it pre-minified with
// an embedded WASM blob, so there's no more-readable form to preserve — unlike crypto-js.
// module.js, unminifying this wouldn't recover any readable hashing logic). Only reformatted
// from UMD to a real ES module (native `import`/`export`) via esbuild, same reason as
// crypto-js.module.js: `require(...)` isn't valid syntax for a browser's native module loader.
// To rebuild after upgrading hash-wasm, `npm pack hash-wasm`, extract it, and run esbuild
// against an entry.mjs containing:
//
//   import * as whirlpoolModule from './dist/whirlpool.umd.min.js'
//   export const whirlpool = whirlpoolModule.whirlpool
//
//   esbuild entry.mjs --bundle --format=esm --outfile=hash-wasm-whirlpool.module.js
var __create = Object.create;
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __getProtoOf = Object.getPrototypeOf;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __commonJS = (cb, mod) => function __require() {
  try {
    return mod || (0, cb[__getOwnPropNames(cb)[0]])((mod = { exports: {} }).exports, mod), mod.exports;
  } catch (e) {
    throw mod = 0, e;
  }
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toESM = (mod, isNodeMode, target) => (target = mod != null ? __create(__getProtoOf(mod)) : {}, __copyProps(
  // If the importer is in node compatibility mode or this is not an ESM
  // file that has been converted to a CommonJS file using a Babel-
  // compatible transform (i.e. "__esModule" has not been set), then set
  // "default" to the CommonJS "module.exports" for node compatibility.
  isNodeMode || !mod || !mod.__esModule ? __defProp(target, "default", { value: mod, enumerable: true }) : target,
  mod
));

// package/dist/whirlpool.umd.min.js
var require_whirlpool_umd_min = __commonJS({
  "package/dist/whirlpool.umd.min.js"(exports, module) {
    !(function(A, e) {
      "object" == typeof exports && "undefined" != typeof module ? e(exports) : "function" == typeof define && define.amd ? define(["exports"], e) : e((A = "undefined" != typeof globalThis ? globalThis : A || self).hashwasm = A.hashwasm || {});
    })(exports, (function(A) {
      "use strict";
      var e, Q = { name: "whirlpool", data: "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", hash: "8d8f6035" };
      function B(A2, e2, Q2, B2) {
        return new (Q2 || (Q2 = Promise))((function(t2, i2) {
          function I2(A3) {
            try {
              o2(B2.next(A3));
            } catch (A4) {
              i2(A4);
            }
          }
          function n2(A3) {
            try {
              o2(B2.throw(A3));
            } catch (A4) {
              i2(A4);
            }
          }
          function o2(A3) {
            var e3;
            A3.done ? t2(A3.value) : (e3 = A3.value, e3 instanceof Q2 ? e3 : new Q2((function(A4) {
              A4(e3);
            }))).then(I2, n2);
          }
          o2((B2 = B2.apply(A2, e2 || [])).next());
        }));
      }
      "function" == typeof SuppressedError && SuppressedError;
      class t {
        constructor() {
          this.mutex = Promise.resolve();
        }
        lock() {
          let A2 = () => {
          };
          return this.mutex = this.mutex.then((() => new Promise(A2))), new Promise(((e2) => {
            A2 = e2;
          }));
        }
        dispatch(A2) {
          return B(this, void 0, void 0, (function* () {
            const e2 = yield this.lock();
            try {
              return yield Promise.resolve(A2());
            } finally {
              e2();
            }
          }));
        }
      }
      const i = "undefined" != typeof globalThis ? globalThis : "undefined" != typeof self ? self : "undefined" != typeof window ? window : global, I = null !== (e = i.Buffer) && void 0 !== e ? e : null, n = i.TextEncoder ? new i.TextEncoder() : null;
      function o(A2, e2) {
        return (15 & A2) + (A2 >> 6 | A2 >> 3 & 8) << 4 | (15 & e2) + (e2 >> 6 | e2 >> 3 & 8);
      }
      const r = "a".charCodeAt(0) - 10, C = "0".charCodeAt(0);
      function g(A2, e2, Q2) {
        let B2 = 0;
        for (let t2 = 0; t2 < Q2; t2++) {
          let Q3 = e2[t2] >>> 4;
          A2[B2++] = Q3 > 9 ? Q3 + r : Q3 + C, Q3 = 15 & e2[t2], A2[B2++] = Q3 > 9 ? Q3 + r : Q3 + C;
        }
        return String.fromCharCode.apply(null, A2);
      }
      const E = null !== I ? (A2) => {
        if ("string" == typeof A2) {
          const e2 = I.from(A2, "utf8");
          return new Uint8Array(e2.buffer, e2.byteOffset, e2.length);
        }
        if (I.isBuffer(A2)) return new Uint8Array(A2.buffer, A2.byteOffset, A2.length);
        if (ArrayBuffer.isView(A2)) return new Uint8Array(A2.buffer, A2.byteOffset, A2.byteLength);
        throw new Error("Invalid data type!");
      } : (A2) => {
        if ("string" == typeof A2) return n.encode(A2);
        if (ArrayBuffer.isView(A2)) return new Uint8Array(A2.buffer, A2.byteOffset, A2.byteLength);
        throw new Error("Invalid data type!");
      }, a = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", s = new Uint8Array(256);
      for (let A2 = 0; A2 < a.length; A2++) s[a.charCodeAt(A2)] = A2;
      function c(A2) {
        const e2 = (function(A3) {
          let e3 = Math.floor(0.75 * A3.length);
          const Q3 = A3.length;
          return "=" === A3[Q3 - 1] && (e3 -= 1, "=" === A3[Q3 - 2] && (e3 -= 1)), e3;
        })(A2), Q2 = A2.length, B2 = new Uint8Array(e2);
        let t2 = 0;
        for (let e3 = 0; e3 < Q2; e3 += 4) {
          const Q3 = s[A2.charCodeAt(e3)], i2 = s[A2.charCodeAt(e3 + 1)], I2 = s[A2.charCodeAt(e3 + 2)], n2 = s[A2.charCodeAt(e3 + 3)];
          B2[t2] = Q3 << 2 | i2 >> 4, t2 += 1, B2[t2] = (15 & i2) << 4 | I2 >> 2, t2 += 1, B2[t2] = (3 & I2) << 6 | 63 & n2, t2 += 1;
        }
        return B2;
      }
      const w = 16384, h = new t(), f = /* @__PURE__ */ new Map();
      function l(A2, e2) {
        return B(this, void 0, void 0, (function* () {
          let Q2 = null, t2 = null, i2 = false;
          if ("undefined" == typeof WebAssembly) throw new Error("WebAssembly is not supported in this environment!");
          const I2 = () => new DataView(Q2.exports.memory.buffer).getUint32(Q2.exports.STATE_SIZE, true), n2 = h.dispatch((() => B(this, void 0, void 0, (function* () {
            if (!f.has(A2.name)) {
              const e4 = c(A2.data), Q3 = WebAssembly.compile(e4);
              f.set(A2.name, Q3);
            }
            const e3 = yield f.get(A2.name);
            Q2 = yield WebAssembly.instantiate(e3, {});
          })))), r2 = (A3 = null) => {
            i2 = true, Q2.exports.Hash_Init(A3);
          }, C2 = (A3) => {
            if (!i2) throw new Error("update() called before init()");
            ((A4) => {
              let e3 = 0;
              for (; e3 < A4.length; ) {
                const B2 = A4.subarray(e3, e3 + w);
                e3 += B2.length, t2.set(B2), Q2.exports.Hash_Update(B2.length);
              }
            })(E(A3));
          }, a2 = new Uint8Array(2 * e2), s2 = (A3, B2 = null) => {
            if (!i2) throw new Error("digest() called before init()");
            return i2 = false, Q2.exports.Hash_Final(B2), "binary" === A3 ? t2.slice(0, e2) : g(a2, t2, e2);
          }, l2 = (A3) => "string" == typeof A3 ? A3.length < 4096 : A3.byteLength < w;
          let k2 = l2;
          switch (A2.name) {
            case "argon2":
            case "scrypt":
              k2 = () => true;
              break;
            case "blake2b":
            case "blake2s":
              k2 = (A3, e3) => e3 <= 512 && l2(A3);
              break;
            case "blake3":
              k2 = (A3, e3) => 0 === e3 && l2(A3);
              break;
            case "xxhash64":
            case "xxhash3":
            case "xxhash128":
            case "crc64":
              k2 = () => false;
          }
          return yield (() => B(this, void 0, void 0, (function* () {
            Q2 || (yield n2);
            const A3 = Q2.exports.Hash_GetBuffer(), e3 = Q2.exports.memory.buffer;
            t2 = new Uint8Array(e3, A3, w);
          })))(), { getMemory: () => t2, writeMemory: (A3, e3 = 0) => {
            t2.set(A3, e3);
          }, getExports: () => Q2.exports, setMemorySize: (A3) => {
            Q2.exports.Hash_SetMemorySize(A3);
            const e3 = Q2.exports.Hash_GetBuffer(), B2 = Q2.exports.memory.buffer;
            t2 = new Uint8Array(B2, e3, A3);
          }, init: r2, update: C2, digest: s2, save: () => {
            if (!i2) throw new Error("save() can only be called after init() and before digest()");
            const e3 = Q2.exports.Hash_GetState(), B2 = I2(), t3 = Q2.exports.memory.buffer, n3 = new Uint8Array(t3, e3, B2), r3 = new Uint8Array(4 + B2);
            return (function(A3, e4) {
              const Q3 = e4.length >> 1;
              for (let B3 = 0; B3 < Q3; B3++) {
                const Q4 = B3 << 1;
                A3[B3] = o(e4.charCodeAt(Q4), e4.charCodeAt(Q4 + 1));
              }
            })(r3, A2.hash), r3.set(n3, 4), r3;
          }, load: (e3) => {
            if (!(e3 instanceof Uint8Array)) throw new Error("load() expects an Uint8Array generated by save()");
            const B2 = Q2.exports.Hash_GetState(), t3 = I2(), n3 = 4 + t3, r3 = Q2.exports.memory.buffer;
            if (e3.length !== n3) throw new Error(`Bad state length (expected ${n3} bytes, got ${e3.length})`);
            if (!(function(A3, e4) {
              if (A3.length !== 2 * e4.length) return false;
              for (let Q3 = 0; Q3 < e4.length; Q3++) {
                const B3 = Q3 << 1;
                if (e4[Q3] !== o(A3.charCodeAt(B3), A3.charCodeAt(B3 + 1))) return false;
              }
              return true;
            })(A2.hash, e3.subarray(0, 4))) throw new Error("This state was written by an incompatible hash implementation");
            const C3 = e3.subarray(4);
            new Uint8Array(r3, B2, t3).set(C3), i2 = true;
          }, calculate: (A3, B2 = null, i3 = null) => {
            if (!k2(A3, B2)) return r2(B2), C2(A3), s2("hex", i3);
            const I3 = E(A3);
            return t2.set(I3), Q2.exports.Hash_Calculate(I3.length, B2, i3), g(a2, t2, e2);
          }, hashLength: e2 };
        }));
      }
      const k = new t();
      let D = null;
      A.createWhirlpool = function() {
        return l(Q, 64).then(((A2) => {
          A2.init();
          const e2 = { init: () => (A2.init(), e2), update: (Q2) => (A2.update(Q2), e2), digest: (e3) => A2.digest(e3), save: () => A2.save(), load: (Q2) => (A2.load(Q2), e2), blockSize: 64, digestSize: 64 };
          return e2;
        }));
      }, A.whirlpool = function(A2) {
        if (null === D) return (function(A3, e2, Q2) {
          return B(this, void 0, void 0, (function* () {
            const B2 = yield A3.lock(), t2 = yield l(e2, Q2);
            return B2(), t2;
          }));
        })(k, Q, 64).then(((e2) => (D = e2, D.calculate(A2))));
        try {
          const e2 = D.calculate(A2);
          return Promise.resolve(e2);
        } catch (A3) {
          return Promise.reject(A3);
        }
      };
    }));
  }
});

// entry.mjs
var whirlpoolModule = __toESM(require_whirlpool_umd_min(), 1);
var whirlpool2 = whirlpoolModule.whirlpool;
export {
  whirlpool2 as whirlpool
};
/*!
 * hash-wasm (https://www.npmjs.com/package/hash-wasm)
 * (c) Dani Biro
 * @license MIT
 */
