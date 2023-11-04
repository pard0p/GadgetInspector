# CallstackSpoofing_Detector
Gadget-based Callstack Spoofing Detector.

Tested on:
https://github.com/pard0p/CallstackSpoofingPOC

It should detect:
https://github.com/klezVirus/SilentMoonwalk

## How to use it?

```bash
callstackspoof_detector.exe -p <PID> or --pid <PID>
callstackspoof_detector.exe -o <NAME> or --output <NAME>
```

Example:
```bash
callstackspoof_detector.exe -p 1000 -o out.txt
```

## To compile
```bash
g++ .\callstackspoof_detector.cpp -o .\callstackspoof_detector.exe -ldbghelp
```

## WARNING
This is an UNFINISHED proof of concept. Certain situations can cause false positives.
