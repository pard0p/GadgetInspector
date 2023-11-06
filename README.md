# GadgetInspector - Gadget-based Callstack Spoofing Detector

![image](https://github.com/pard0p/GadgetInspector/assets/79936108/678cc7d1-15ff-42c6-a911-fccba1d10b44)

## Tested on:
https://github.com/pard0p/CallstackSpoofingPOC

It should also detect:
https://github.com/klezVirus/SilentMoonwalk

## How to use it?

```bash
gadget_inspector.exe -p <PID> or --pid <PID>
gadget_inspector.exe -o <NAME> or --output <NAME>
```

Example:
```bash
gadget_inspector.exe -p 1000 -o out.txt
```

All PIDs: 
```bash
gadget_inspector.exe -o out.txt
```

## To compile
```bash
g++ .\gadget_inspector.cpp -o .\gadget_inspector.exe -ldbghelp
```

## WARNING
This is an UNFINISHED proof of concept. Certain situations can cause false positives.
