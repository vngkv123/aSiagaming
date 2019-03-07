## Exploit Demo
https://youtu.be/jogKNuw9dUs
## Patch
```diff
diff --git a/Source/JavaScriptCore/dfg/DFGAbstractInterpreterInlines.h b/Source/JavaScriptCore/dfg/DFGAbstractInterpreterInlines.h
--- a/Source/JavaScriptCore/dfg/DFGAbstractInterpreterInlines.h
+++ b/Source/JavaScriptCore/dfg/DFGAbstractInterpreterInlines.h
@@ -3527,7 +3527,7 @@ bool AbstractInterpreter<AbstractStateType>::executeEffects(unsigned clobberLimi
     }
     case GetPropertyEnumerator: {
         setTypeForNode(node, SpecCell);
-        clobberWorld();
+        //clobberWorld();
         break;
     }
     case GetEnumeratorStructurePname: {
diff --git a/Source/JavaScriptCore/dfg/DFGClobberize.h b/Source/JavaScriptCore/dfg/DFGClobberize.h
--- a/Source/JavaScriptCore/dfg/DFGClobberize.h
+++ b/Source/JavaScriptCore/dfg/DFGClobberize.h
@@ -280,6 +280,9 @@ void clobberize(Graph& graph, Node* node, const ReadFunctor& read, const WriteFu
         read(MathDotRandomState);
         write(MathDotRandomState);
         return;
+    case HasGenericProperty:
+    case HasStructureProperty:
+    case GetPropertyEnumerator:
     case GetEnumerableLength: {
         read(Heap);
@@ -646,10 +649,7 @@ void clobberize(Graph& graph, Node* node, const ReadFunctor& read, const WriteFu
     case ResolveScopeForHoistingFuncDeclInEval:
     case ResolveScope:
     case ToObject:
-    case HasGenericProperty:
-    case HasStructureProperty:
-    case GetPropertyEnumerator:
     case GetDirectPname:
     case InstanceOfCustom:
     case ToNumber:
     case NumberToStringWithRadix:


diff --git a/Source/WebKit/Shared/mac/ChildProcessMac.mm b/Source/WebKit/Shared/mac/ChildProcessMac.mm
--- a/Source/WebKit/Shared/mac/ChildProcessMac.mm
+++ b/Source/WebKit/Shared/mac/ChildProcessMac.mm
@@ -526,7 +526,7 @@ static void getSandboxProfileOrProfilePath(const SandboxInitializationParameters

 static bool compileAndApplySandboxSlowCase(const String& profileOrProfilePath, bool isProfilePath, const SandboxInitializationParameters& parameters)
 {
-    char* errorBuf;
+    /*char* errorBuf;
     CString temp = isProfilePath ? FileSystem::fileSystemRepresentation(profileOrProfilePath) : profileOrProfilePath.utf8();
     uint64_t flags = isProfilePath ? SANDBOX_NAMED_EXTERNAL : 0;
     ALLOW_DEPRECATED_DECLARATIONS_BEGIN
@@ -536,7 +536,7 @@ static bool compileAndApplySandboxSlowCase(const String& profileOrProfilePath, b
         for (size_t i = 0, count = parameters.count(); i != count; ++i)
             WTFLogAlways("%s=%s\n", parameters.name(i), parameters.value(i));
         return false;
-    }
+    }*/
     return true;
 }

@@ -550,7 +550,8 @@ static bool applySandbox(const ChildProcessInitializationParameters& parameters,
         CRASH();
     }

-#if USE(CACHE_COMPILED_SANDBOX)
+//#if USE(CACHE_COMPILED_SANDBOX)
+#if 0
     // The plugin process's DARWIN_USER_TEMP_DIR and DARWIN_USER_CACHE_DIR sandbox parameters are randomized so
     // so the compiled sandbox should not be cached because it won't be reused.
     if (parameters.processType == ChildProcess::ProcessType::Plugin)


# ./Source/JavaScriptCore/dfg/DFGAbstractInterpreterInlines.h
3607     case GetPropertyEnumerator: {
3608         setTypeForNode(node, SpecCell);
3609         //clobberWorld();
3610         break;
3611     }
# ./Source/JavaScriptCore/dfg/DFGClobberize.h
 290     case HasGenericProperty:
 291     case HasStructureProperty:
 292     case GetPropertyEnumerator:
 293     case GetEnumerableLength: {
 294         read(Heap);
 295         write(SideState);
 296         return;
 297     }
```  
  
  
## Build

I can't run this challenge binary set in my MacBook Pro, i just change Webkit source from current version and build it to exploit. I think we just need to exploit JavaScriptCore itself because Sandbox related code is removed in patch code, so sandbox escape is not needed.

## Analysis
"GetPropertyEnumerator" opcode is most important part of this vulnerability.
Because, "GetPropertyEnumerator" actually have side-effect, but in patch code, it remove "clobberWorld()" which means this operation is side-effect-free. So, in "GetPropertyEnumerator" operation, although we violate some previous type assumption, optimized code doesn't bailout.
Using this vulnerability, we can make type confusion between unboxed double array and boxed(contiguous) array.

## Webkit DFG Commit
* https://github.com/WebKit/webkit/commit/243a17dd57da84426316502c5346766429f2456d
As above commit log showed, he said that this operation has side-effect, and give some test js code.
Actually, i'm quite stucked in how to make some side effect code during "getPropertyEnumerator" operation.
I know that "getPropertyEnumerator" code is generated in "for .. in" statement, but i don't have any idea how to trigger side effect :(
I tried many things to trigger side effect.
Using custom getter or Proxy getter is not good options because these are triggered only when property's element is accessed.
After the research, i'm sure that using the Proxy object is only way to solve this problem.
And that's correct ! In Proxy Object, Proxy has "getPrototypeOf" member :)
Before using this, we need to know how "for .. in" statement works.
Simple example is following one.

```js
let a = {x: 1, y: 2, z: 3};
a.__proto__ = {xx: 1, yy: 2, zz: 3};

for(let i in a) {
    print(i);
}
```

"for .. in" statement traverse Object's prototype chain.
And, Proxy's "getPrototypeOf" is trap method for prototype lookup :)
Now, we know how to make side effect during this operation work !
Using this, we can easily make addrof and fakeobj primitivies.
Basic exploitation methods are well described at @saelo's phrack article.
