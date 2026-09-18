# Building

## Prerequisites

- **Visual Studio 2022** (or newer) with the **Desktop development with C++**
  workload.
- **MSVC v143/v145** platform toolset (v145 is used for x64).
- Windows 10/11 SDK.

## Build steps

Open `client.sln` in Visual Studio, or build from the command line:

```powershell
msbuild client.sln /p:Configuration=Release /p:Platform=x64
```

The solution is **configured for x64 Release only** - the Debug and Win32
configurations have been removed.

## Output

The output is a 64-bit DLL at:

```
build\client.dll
```

Intermediate object files land in `build\obj\`. Both directories are
auto-generated and safe to delete.
