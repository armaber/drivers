Generate `.vcxproj`
---

*Visual Studio 2022* is the established IDE for driver development. VS Code's prevalence can require a
back-and-forth to obtain the project file to continue coding inside Code.

Templates for many project types are created from CLI. The benefit is a default `.vcxproj` with build
configurations that offer coverage and safety: `stdc17`, `Spectre`, `static analysis`, `clang-tidy`.

The build script `.\GenerateVcxproj.ps1` is *work in progress*:

- use `-Wdm` or `-Kmdf` for the driver model
- specify `-Service` to create a control device object
- `-NtddiVersion` can override default `NTDDI_WIN10`
- pass a `-CertificatePath` to populate `<TestCertificate>` field

On completion, it overwrites without warning the *.vcxproj, .vcxproj.user* files. If there is no `driver.c`
present, it writes a simple one.

Project file enables static analysis on build and clang-tidy. There is a bug in Visual Studio, where
default project wizard inserts a `%(ClCompile.AdditionalOptions)` in *Project Properties &#x2192; C/C++ &#x2192;
All Options &#x2192; AdditionalOptions*, preventing the build. This shortcoming is bypassed.

Where *CodeQL* is installed, the script displays commands to integrate with `microsoft/windows-drivers` pack.
