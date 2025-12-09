"use strict";

function parseClipboard() {
    let console = { log: host.diagnostics.debugLog };
    let controller = host.namespace.Debugger.Utility.Control;
    let lines = controller.ExecuteCommand('.shell -ci " " pwsh.exe -NoProfile -ExecutionPolicy Bypass -Command "Out-Null; Get-Clipboard"');
    for (let line of lines) {
        line = line.trim();
        if (line.length === 0) {
            continue;
        }
        if (line.match(/\.shell/)) {
            continue;
        }
        line = line.replace("Stack ", "");
        let output = controller.ExecuteCommand(`u ${line} L1`);
        let hit = output[0].split(/ [0-9a-f]+ /)[0];
        if (hit[hit.length - 1] != ':') {
            console.log(hit + " // symbol not loaded or module is unloaded\n");
        } else {
            hit = hit.replace(/:$/, "");
            console.log(`${hit}\n`);
        }
    }
}

/*
    Copy the stack frames to the clipboard and execute with 
     .scriptrun <FullPathToThisScript>
    
    Example at line 2331 in .\SampleOutput.txt.
*/
function invokeScript()
{
    parseClipboard();
}
