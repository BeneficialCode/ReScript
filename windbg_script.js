/// <reference path="JsProvider.d.ts" />
"use strict";

function initializeScript()
{
    //
    // Return an array of registration objects to modify the object model of the debugger
    // See the following for more details:
    //
    //     https://aka.ms/JsDbgExt
    //
    return [new host.apiVersionSupport(1, 7)];
}

let logln = function (e) {
    host.diagnostics.debugLog(e + '\n');
}

function read_16byte(addr){
    return host.memory.readMemoryValues(addr,16,1);
}

function handle_bp(){
    let Regs = host.currentThread.Registers.User;
    let addr = Regs.esp;
    let bytes = read_16byte(addr);
    logln("breakpoint!");
}

function invokeScript()
{
    host.diagnostics.debugLog("Hello World!\n");
    let Regs = host.currentThread.Registers.User;
    let bytes = read_16byte(Regs.esp);
    let Control = host.namespace.Debugger.Utility.Control;
    var base = host.currentProcess.Environment.EnvironmentBlock.ImageBaseAddress;
    // and then ?
}