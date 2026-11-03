# ANTIVIRUS FLAGS & FALSE POSITIVE NOTICE

If you upload and scan the uncompiled source files (danbooru_service.py, index.html, project.json) individually through VirusTotal, there are 0 FLAGS across all security vendors (completely clean).

The detections occur purely as a byproduct of packaging the Python runtime into a standalone Windows executable using PyInstaller combined with low-level Windows desktop API calls.

----------------------------------------------------------------------

## DETECTION BREAKDOWN

1. Trojan:Win32/Wacatac.C!ml

   - Scanner / Engine: Microsoft Defender

   - Meaning: The "!ml" suffix explicitly designates Machine Learning. Defender did not match any known malicious signature in the source code.

   - Why it was flagged: Defender's automated cloud algorithm flagged the binary based on heuristic patterns because the unsigned PyInstaller compression stub shares architectural characteristics with generic executable wrappers.

2. Static AI - Suspicious PE

   - Scanner / Engine: Heuristic AI Scanner

   - Meaning: "PE" stands for Portable Executable (the standard Windows binary format). This is a pre-execution static inspection flag.

   - Why it was flagged: The scanner inspects binary section headers without executing the file. It triggers when it detects packed, high-entropy data sections (the compressed Python runtime and bundled assets) that resemble binary packers frequently seen in unauthorized software.


3. W32.Malware.77C9E130

   - Scanner / Engine: Generic Heuristic Engine

   - Meaning: An automated heuristic hash definition.

   - Why it was flagged: It is assigned automatically to newly compiled, unsigned binaries that have zero prior global download history and low reputation scores.


----------------------------------------------------------------------

## WHY DOES THE STANDALONE EXECUTABLE GET FLAGGED?

The flags are caused by an overlap between standard desktop wallpaper engine mechanics and automated security heuristic rules:

* PyInstaller Compression (--onefile):

  PyInstaller bundles Python, its required libraries, and assets into a single executable. At launch, the bootloader automatically unpacks dynamic libraries into your user temporary directory (%TEMP%\_MEIxxxxxx). Because some malware distributors bundle payloads using generic PyInstaller stubs, heuristic models frequently flag clean PyInstaller files simply by association.


* Desktop Shell Hooking (user32.dll via ctypes):

  To embed the live webview behind your desktop icons without relying on third-party software, the application uses standard Win32 calls (0x052C message to Progman, WorkerW discovery, and SetParent). While this is the identical technique used by legitimate tools like Wallpaper Engine and Lively Wallpaper, heuristic engines treat shell window reparenting by unsigned binaries with suspicion.


* Silent Background Execution (--noconsole) + Local Host:

  The application runs without an attached console window and binds an internal loopback HTTP server (127.0.0.1:8088) to stream images locally to the webview. Antivirus heuristics monitor executables that combine a hidden window state with local network socket binding.


* Lack of an Expensive Code-Signing Certificate:

  Windows security systems rely heavily on commercial digital signatures. As an independent open-source project without a costly enterprise code-signing certificate (e.g., DigiCert or Sectigo), newly generated binary hashes automatically begin with zero trust reputation.


----------------------------------------------------------------------

## HOW TO VERIFY THE CODE YOURSELF


- Inspect the Source Code:

  The entire application is open source. You can inspect every network request and Win32 call directly in the repository.

- Scan the Source Files:

  Upload danbooru_service.py directly to VirusTotal (https://www.virustotal.com/). It will return 0 detections.

- Build or Run Directly from Source:

  If you prefer not to run precompiled binaries, you can run the script directly using your local Python interpreter: python danbooru_service.py
