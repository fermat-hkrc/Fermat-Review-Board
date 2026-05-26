## PoC 验证

**方法**: Target-Compile — 编译真实 `jpeg_yuvdata_converter.cpp` 和 `yuv_helper.cpp` 为 `.o`，链接 ASan 插桩二进制，通过公共 API `I400ToI420_wrapper` 触发。

**触发路径**:
```
main → I400ToI420_wrapper(src, dest)
     → YuvHelper::GetInstance().I400ToI420 == nullptr (无 libyuv.z.so)
     → 进入 else fallback 路径
       → UVCOMSize = 32*32 + 32*32 = 2048
       → memset_s(dest.planes[UCOM], 2048, 0x80, 2048)
         → dest.planes[UCOM] 仅分配 1024 字节
         → ASan: heap-buffer-overflow WRITE of size 2048
```

**ASan 输出**:
```
==2785689==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x519000000480
WRITE of size 2048 at 0x519000000480 thread T0
    #0 in memset
    #1 in memset_s stubs/securec.h:14
    #2 in OHOS::ImagePlugin::I400ToI420_wrapper()
       jpeg_yuvdata_converter.cpp:346
    #3 in main poc_yuv_i400_overflow.cpp:100
    #4 in __libc_start_call_main
    #5 in __libc_start_main_impl
0x519000000480 is located 0 bytes after 1024-byte region [0x519000000080,0x519000000480)
allocated by thread T0 here:
    #0 in malloc
    #1 in main poc_yuv_i400_overflow.cpp:55
SUMMARY: AddressSanitizer: heap-buffer-overflow in memset
```

**二进制验证** (`nm` 确认链接真实符号):
```
T OHOS::ImagePlugin::I400ToI420_wrapper(...)
T OHOS::ImagePlugin::I4xxToI420_c(...)
t OHOS::ImagePlugin::CopyYData(...)
t OHOS::ImagePlugin::SampleUV(...)
T OHOS::ImagePlugin::YuvHelper::GetInstance()
T OHOS::ImagePlugin::YuvHelper::YuvHelper()
```

