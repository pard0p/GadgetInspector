# CallstackSpoofing_Detector
Callstack Spoof based on gadjets detector.

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
