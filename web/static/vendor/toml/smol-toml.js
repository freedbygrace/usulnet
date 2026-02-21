// smol-toml v1.3.1 — BSD-3-Clause — bundled as IIFE for browser use
// Original: https://github.com/nicbarker/smol-toml
(function(global) {
function R(e,n){let i=e.slice(0,n).split(/\r\n|\n|\r/g);return[i.length,i.pop().length+1]}function Z(e,n,i){let l=e.split(/\r\n|\n|\r/g),r="",t=(Math.log10(n+1)|0)+1;for(let f=n-1;f<=n+1;f++){let o=l[f-1];o&&(r+=f.toString().padEnd(t," "),r+=":  ",r+=o,r+=`
`,f===n&&(r+=" ".repeat(t+i+2),r+=`^
`))}return r}var c=class extends Error{line;column;codeblock;constructor(n,i){let[l,r]=R(i.toml,i.ptr),t=Z(i.toml,l,r);super(`Invalid TOML document: ${n}

${t}`,i),this.line=l,this.column=r,this.codeblock=t}};function s(e,n=0,i=e.length){let l=e.indexOf(`
`,n);return e[l-1]==="\r"&&l--,l<=i?l:-1}function h(e,n){for(let i=n;i<e.length;i++){let l=e[i];if(l===`
`)return i;if(l==="\r"&&e[i+1]===`
`)return i+1;if(l<" "&&l!=="	"||l==="\x7F")throw new c("control characters are not allowed in comments",{toml:e,ptr:n})}return e.length}function m(e,n,i,l){let r;for(;(r=e[n])===" "||r==="	"||!i&&(r===`
`||r==="\r"&&e[n+1]===`
`);)n++;return l||r!=="#"?n:m(e,h(e,n),i)}function T(e,n,i,l,r=!1){if(!l)return n=s(e,n),n<0?e.length:n;for(let t=n;t<e.length;t++){let f=e[t];if(f==="#")t=s(e,t);else{if(f===i)return t+1;if(f===l)return t;if(r&&(f===`
`||f==="\r"&&e[t+1]===`
`))return t}}throw new c("cannot find end of structure",{toml:e,ptr:n})}function x(e,n){let i=e[n],l=i===e[n+1]&&e[n+1]===e[n+2]?e.slice(n,n+3):i;n+=l.length-1;do n=e.indexOf(l,++n);while(n>-1&&i!=="'"&&e[n-1]==="\\"&&e[n-2]!=="\\");return n>-1&&(n+=l.length,l.length>1&&(e[n]===i&&n++,e[n]===i&&n++)),n}var j=/^(\d{4}-\d{2}-\d{2})?[T ]?(?:(\d{2}):\d{2}:\d{2}(?:\.\d+)?)?(Z|[-+]\d{2}:\d{2})?$/i,w=class e extends Date{#n=!1;#t=!1;#e=null;constructor(n){let i=!0,l=!0,r="Z";if(typeof n=="string"){let t=n.match(j);t?(t[1]||(i=!1,n=`0000-01-01T${n}`),l=!!t[2],t[2]&&+t[2]>23?n="":(r=t[3]||null,n=n.toUpperCase(),!r&&l&&(n+="Z"))):n=""}super(n),isNaN(this.getTime())||(this.#n=i,this.#t=l,this.#e=r)}isDateTime(){return this.#n&&this.#t}isLocal(){return!this.#n||!this.#t||!this.#e}isDate(){return this.#n&&!this.#t}isTime(){return this.#t&&!this.#n}isValid(){return this.#n||this.#t}toISOString(){let n=super.toISOString();if(this.isDate())return n.slice(0,10);if(this.isTime())return n.slice(11,23);if(this.#e===null)return n.slice(0,-1);if(this.#e==="Z")return n;let i=+this.#e.slice(1,3)*60+ +this.#e.slice(4,6);return i=this.#e[0]==="-"?i:-i,new Date(this.getTime()-i*6e4).toISOString().slice(0,-1)+this.#e}static wrapAsOffsetDateTime(n,i="Z"){let l=new e(n);return l.#e=i,l}static wrapAsLocalDateTime(n){let i=new e(n);return i.#e=null,i}static wrapAsLocalDate(n){let i=new e(n);return i.#t=!1,i.#e=null,i}static wrapAsLocalTime(n){let i=new e(n);return i.#n=!1,i.#e=null,i}};var z=/^((0x[0-9a-fA-F](_?[0-9a-fA-F])*)|(([+-]|0[ob])?\d(_?\d)*))$/,K=/^[+-]?\d(_?\d)*(\.\d(_?\d)*)?([eE][+-]?\d(_?\d)*)?$/,M=/^[+-]?0[0-9_]/,F=/^[0-9a-f]{4,8}$/i,k={b:"\b",t:"	",n:`
`,f:"\f",r:"\r",'"':'"',"\\":"\\"};function b(e,n=0,i=e.length){let l=e[n]==="'",r=e[n++]===e[n]&&e[n]===e[n+1];r&&(i-=2,e[n+=2]==="\r"&&n++,e[n]===`
`&&n++);let t=0,f,o="",a=n;for(;n<i-1;){let u=e[n++];if(u===`
`||u==="\r"&&e[n]===`
`){if(!r)throw new c("newlines are not allowed in strings",{toml:e,ptr:n-1})}else if(u<" "&&u!=="	"||u==="\x7F")throw new c("control characters are not allowed in strings",{toml:e,ptr:n-1});if(f){if(f=!1,u==="u"||u==="U"){let d=e.slice(n,n+=u==="u"?4:8);if(!F.test(d))throw new c("invalid unicode escape",{toml:e,ptr:t});try{o+=String.fromCodePoint(parseInt(d,16))}catch{throw new c("invalid unicode escape",{toml:e,ptr:t})}}else if(r&&(u===`
`||u===" "||u==="	"||u==="\r")){if(n=m(e,n-1,!0),e[n]!==`
`&&e[n]!=="\r")throw new c("invalid escape: only line-ending whitespace may be escaped",{toml:e,ptr:t});n=m(e,n)}else if(u in k)o+=k[u];else throw new c("unrecognized escape sequence",{toml:e,ptr:t});a=n}else!l&&u==="\\"&&(t=n-1,f=!0,o+=e.slice(a,t))}return o+e.slice(a,i-1)}function D(e,n,i){if(e==="true")return!0;if(e==="false")return!1;if(e==="-inf")return-1/0;if(e==="inf"||e==="+inf")return 1/0;if(e==="nan"||e==="+nan"||e==="-nan")return NaN;if(e==="-0")return 0;let l;if((l=z.test(e))||K.test(e)){if(M.test(e))throw new c("leading zeroes are not allowed",{toml:n,ptr:i});let t=+e.replace(/_/g,"");if(isNaN(t))throw new c("invalid number",{toml:n,ptr:i});if(l&&!Number.isSafeInteger(t))throw new c("integer value cannot be represented losslessly",{toml:n,ptr:i});return t}let r=new w(e);if(!r.isValid())throw new c("invalid value",{toml:n,ptr:i});return r}function G(e,n,i,l){let r=e.slice(n,i),t=r.indexOf("#");t>-1&&(h(e,t),r=r.slice(0,t));let f=r.trimEnd();if(!l){let o=r.indexOf(`
`,f.length);if(o>-1)throw new c("newlines are not allowed in inline tables",{toml:e,ptr:n+o})}return[f,t]}function g(e,n,i,l){if(l===0)throw new c("document contains excessively nested structures. aborting.",{toml:e,ptr:n});let r=e[n];if(r==="["||r==="{"){let[o,a]=r==="["?$(e,n,l):I(e,n,l),u=T(e,a,",",i);if(i==="}"){let d=s(e,a,u);if(d>-1)throw new c("newlines are not allowed in inline tables",{toml:e,ptr:d})}return[o,u]}let t;if(r==='"'||r==="'"){t=x(e,n);let o=b(e,n,t);if(i){if(t=m(e,t,i!=="]"),e[t]&&e[t]!==","&&e[t]!==i&&e[t]!==`
`&&e[t]!=="\r")throw new c("unexpected character encountered",{toml:e,ptr:t});t+=+(e[t]===",")}return[o,t]}t=T(e,n,",",i);let f=G(e,n,t-+(e[t-1]===","),i==="]");if(!f[0])throw new c("incomplete key-value declaration: no value specified",{toml:e,ptr:n});return i&&f[1]>-1&&(t=m(e,n+f[1]),t+=+(e[t]===",")),[D(f[0],e,n),t]}var U=/^[a-zA-Z0-9-_]+[ \t]*$/;function E(e,n,i="="){let l=n-1,r=[],t=e.indexOf(i,n);if(t<0)throw new c("incomplete key-value: cannot find end of key",{toml:e,ptr:n});do{let f=e[n=++l];if(f!==" "&&f!=="	")if(f==='"'||f==="'"){if(f===e[n+1]&&f===e[n+2])throw new c("multiline strings are not allowed in keys",{toml:e,ptr:n});let o=x(e,n);if(o<0)throw new c("unfinished string encountered",{toml:e,ptr:n});l=e.indexOf(".",o);let a=e.slice(o,l<0||l>t?t:l),u=s(a);if(u>-1)throw new c("newlines are not allowed in keys",{toml:e,ptr:n+l+u});if(a.trimStart())throw new c("found extra tokens after the string part",{toml:e,ptr:o});if(t<o&&(t=e.indexOf(i,o),t<0))throw new c("incomplete key-value: cannot find end of key",{toml:e,ptr:n});r.push(b(e,n,o))}else{l=e.indexOf(".",n);let o=e.slice(n,l<0||l>t?t:l);if(!U.test(o))throw new c("only letter, numbers, dashes and underscores are allowed in keys",{toml:e,ptr:n});r.push(o.trimEnd())}}while(l+1&&l<t);return[r,m(e,t+1,!0,!0)]}function I(e,n,i){let l={},r=new Set,t,f=0;for(n++;(t=e[n++])!=="}"&&t;){if(t===`
`)throw new c("newlines are not allowed in inline tables",{toml:e,ptr:n-1});if(t==="#")throw new c("inline tables cannot contain comments",{toml:e,ptr:n-1});if(t===",")throw new c("expected key-value, found comma",{toml:e,ptr:n-1});if(t!==" "&&t!=="	"){let o,a=l,u=!1,[d,P]=E(e,n-1);for(let y=0;y<d.length;y++){if(y&&(a=u?a[o]:a[o]={}),o=d[y],(u=Object.hasOwn(a,o))&&(typeof a[o]!="object"||r.has(a[o])))throw new c("trying to redefine an already defined value",{toml:e,ptr:n});!u&&o==="__proto__"&&Object.defineProperty(a,o,{enumerable:!0,configurable:!0,writable:!0})}if(u)throw new c("trying to redefine an already defined value",{toml:e,ptr:n});let[_,v]=g(e,P,"}",i-1);r.add(_),a[o]=_,n=v,f=e[n-1]===","?n-1:0}}if(f)throw new c("trailing commas are not allowed in inline tables",{toml:e,ptr:f});if(!t)throw new c("unfinished table encountered",{toml:e,ptr:n});return[l,n]}function $(e,n,i){let l=[],r;for(n++;(r=e[n++])!=="]"&&r;){if(r===",")throw new c("expected value, found comma",{toml:e,ptr:n-1});if(r==="#")n=h(e,n);else if(r!==" "&&r!=="	"&&r!==`
`&&r!=="\r"){let t=g(e,n-1,"]",i-1);l.push(t[0]),n=t[1]}}if(!r)throw new c("unfinished array encountered",{toml:e,ptr:n});return[l,n]}function N(e,n,i,l){let r=n,t=i,f,o=!1,a;for(let u=0;u<e.length;u++){if(u){if(r=o?r[f]:r[f]={},t=(a=t[f]).c,l===0&&(a.t===1||a.t===2))return null;if(a.t===2){let d=r.length-1;r=r[d],t=t[d].c}}if(f=e[u],(o=Object.hasOwn(r,f))&&t[f]?.t===0&&t[f]?.d)return null;o||(f==="__proto__"&&(Object.defineProperty(r,f,{enumerable:!0,configurable:!0,writable:!0}),Object.defineProperty(t,f,{enumerable:!0,configurable:!0,writable:!0})),t[f]={t:u<e.length-1&&l===2?3:l,d:!1,i:0,c:{}})}if(a=t[f],a.t!==l&&!(l===1&&a.t===3)||(l===2&&(a.d||(a.d=!0,r[f]=[]),r[f].push(r={}),a.c[a.i++]=a={t:1,d:!1,i:0,c:{}}),a.d))return null;if(a.d=!0,l===1)r=o?r[f]:r[f]={};else if(l===0&&o)return null;return[f,r,a.c]}function V(e,n){let i=n?.maxDepth??1e3,l={},r={},t=l,f=r;for(let o=m(e,0);o<e.length;){if(e[o]==="["){let a=e[++o]==="[",u=E(e,o+=+a,"]");if(a){if(e[u[1]-1]!=="]")throw new c("expected end of table declaration",{toml:e,ptr:u[1]-1});u[1]++}let d=N(u[0],l,r,a?2:1);if(!d)throw new c("trying to redefine an already defined table or value",{toml:e,ptr:o});f=d[2],t=d[1],o=u[1]}else{let a=E(e,o),u=N(a[0],t,f,0);if(!u)throw new c("trying to redefine an already defined table or value",{toml:e,ptr:o});let d=g(e,a[1],void 0,i);u[1][u[0]]=d[0],o=d[1]}if(o=m(e,o,!0),e[o]&&e[o]!==`
`&&e[o]!=="\r")throw new c("each key-value declaration must be followed by an end-of-line",{toml:e,ptr:o});o=m(e,o)}return l}var C=/^[a-z0-9-_]+$/i;function p(e){let n=typeof e;if(n==="object"){if(Array.isArray(e))return"array";if(e instanceof Date)return"date"}return n}function X(e){for(let n=0;n<e.length;n++)if(p(e[n])!=="object")return!1;return e.length!=0}function O(e){return JSON.stringify(e).replace(/\x7f/g,"\\u007f")}function S(e,n,i){if(i===0)throw new Error("Could not stringify the object: maximum object depth exceeded");if(n==="number")return isNaN(e)?"nan":e===1/0?"inf":e===-1/0?"-inf":e.toString();if(n==="bigint"||n==="boolean")return e.toString();if(n==="string")return O(e);if(n==="date"){if(isNaN(e.getTime()))throw new TypeError("cannot serialize invalid date");return e.toISOString()}if(n==="object")return B(e,i);if(n==="array")return Y(e,i)}function B(e,n){let i=Object.keys(e);if(i.length===0)return"{}";let l="{ ";for(let r=0;r<i.length;r++){let t=i[r];r&&(l+=", "),l+=C.test(t)?t:O(t),l+=" = ",l+=S(e[t],p(e[t]),n-1)}return l+" }"}function Y(e,n){if(e.length===0)return"[]";let i="[ ";for(let l=0;l<e.length;l++){if(l&&(i+=", "),e[l]===null||e[l]===void 0)throw new TypeError("arrays cannot contain null or undefined values");i+=S(e[l],p(e[l]),n-1)}return i+" ]"}function q(e,n,i){if(i===0)throw new Error("Could not stringify the object: maximum object depth exceeded");let l="";for(let r=0;r<e.length;r++)l+=`[[${n}]]
`,l+=A(e[r],n,i),l+=`

`;return l}function A(e,n,i){if(i===0)throw new Error("Could not stringify the object: maximum object depth exceeded");let l="",r="",t=Object.keys(e);for(let f=0;f<t.length;f++){let o=t[f];if(e[o]!==null&&e[o]!==void 0){let a=p(e[o]);if(a==="symbol"||a==="function")throw new TypeError(`cannot serialize values of type '${a}'`);let u=C.test(o)?o:O(o);if(a==="array"&&X(e[o]))r+=q(e[o],n?`${n}.${u}`:u,i-1);else if(a==="object"){let d=n?`${n}.${u}`:u;r+=`[${d}]
`,r+=A(e[o],d,i-1),r+=`

`}else l+=u,l+=" = ",l+=S(e[o],a,i),l+=`
`}}return`${l}
${r}`.trim()}function L(e,n){if(p(e)!=="object")throw new TypeError("stringify can only be called with an object");let i=n?.maxDepth??1e3;return A(e,"",i)}var Se={parse:V,stringify:L,TomlDate:w,TomlError:c};
/*! Bundled license information:

smol-toml/dist/error.js:
smol-toml/dist/util.js:
smol-toml/dist/date.js:
smol-toml/dist/primitive.js:
smol-toml/dist/extract.js:
smol-toml/dist/struct.js:
smol-toml/dist/parse.js:
smol-toml/dist/stringify.js:
smol-toml/dist/index.js:
  (*!
   * Copyright (c) Squirrel Chat et al., All rights reserved.
   * SPDX-License-Identifier: BSD-3-Clause
   *
   * Redistribution and use in source and binary forms, with or without
   * modification, are permitted provided that the following conditions are met:
   *
   * 1. Redistributions of source code must retain the above copyright notice, this
   *    list of conditions and the following disclaimer.
   * 2. Redistributions in binary form must reproduce the above copyright notice,
   *    this list of conditions and the following disclaimer in the
   *    documentation and/or other materials provided with the distribution.
   * 3. Neither the name of the copyright holder nor the names of its contributors
   *    may be used to endorse or promote products derived from this software without
   *    specific prior written permission.
   *
   * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
   * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
   * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
   * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
   * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
   * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
   * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
   * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
   * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
   * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
   *)
*/
global.TOML = { parse: V, stringify: L };
})(typeof window !== 'undefined' ? window : this);
