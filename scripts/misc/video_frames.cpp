// Reads a video with Windows Media Foundation (the decoder a native launcher would use), prints its format and
// writes PNG frames at the given times. Nothing is downloaded; WMV decoding is part of Windows.
// Build: _tools/build-tools.ps1   Usage: video_frames.exe <video> <out_dir> <seconds> [seconds ...]
#include <windows.h>
#include <mfapi.h>
#include <mfidl.h>
#include <mfreadwrite.h>
#include <propvarutil.h>
#include <wincodec.h>

#include <cmath>
#include <cstdio>
#include <cwchar>
#include <vector>

#pragma comment(lib, "mfplat.lib")
#pragma comment(lib, "mfreadwrite.lib")
#pragma comment(lib, "mfuuid.lib")
#pragma comment(lib, "propsys.lib")
#pragma comment(lib, "windowscodecs.lib")
#pragma comment(lib, "ole32.lib")

template <typename T>
struct Com {
    T *p = nullptr;
    ~Com() { if (p) p->Release(); }
    T **operator&() { return &p; }
    T *operator->() const { return p; }
    operator T *() const { return p; }
};

static void fourcc(const GUID &g, char out[5])
{
    memcpy(out, &g.Data1, 4);
    out[4] = 0;
}

static bool write_png(IWICImagingFactory *wic, const wchar_t *path, UINT w, UINT h, UINT stride, BYTE *pixels)
{
    Com<IWICStream> stream;
    Com<IWICBitmapEncoder> enc;
    Com<IWICBitmapFrameEncode> frame;
    if (FAILED(wic->CreateStream(&stream)) || FAILED(stream->InitializeFromFilename(path, GENERIC_WRITE)) ||
        FAILED(wic->CreateEncoder(GUID_ContainerFormatPng, nullptr, &enc)) ||
        FAILED(enc->Initialize(stream, WICBitmapEncoderNoCache)) || FAILED(enc->CreateNewFrame(&frame, nullptr)) ||
        FAILED(frame->Initialize(nullptr)) || FAILED(frame->SetSize(w, h)))
        return false;
    WICPixelFormatGUID fmt = GUID_WICPixelFormat32bppBGR;
    return SUCCEEDED(frame->SetPixelFormat(&fmt)) && SUCCEEDED(frame->WritePixels(h, stride, stride * h, pixels)) &&
           SUCCEEDED(frame->Commit()) && SUCCEEDED(enc->Commit());
}

int wmain(int argc, wchar_t **argv)
{
    if (argc < 4) {
        fwprintf(stderr, L"usage: video_frames <video> <out_dir> <seconds> [seconds ...]\n");
        return 2;
    }
    CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    MFStartup(MF_VERSION);

    Com<IMFAttributes> attrs;
    MFCreateAttributes(&attrs, 1);
    attrs->SetUINT32(MF_SOURCE_READER_ENABLE_VIDEO_PROCESSING, TRUE);  // let MF convert to RGB32
    Com<IMFSourceReader> reader;
    HRESULT hr = MFCreateSourceReaderFromURL(argv[1], attrs, &reader);
    if (FAILED(hr)) {
        fwprintf(stderr, L"cannot open %ls (0x%08lx)\n", argv[1], hr);
        return 1;
    }

    const DWORD video = (DWORD)MF_SOURCE_READER_FIRST_VIDEO_STREAM;
    Com<IMFMediaType> native;
    if (FAILED(reader->GetNativeMediaType(video, 0, &native))) {
        // Audio-only file: report the stream and decode one block to PCM to prove playback would work.
        Com<IMFMediaType> a;
        const DWORD audio_stream = (DWORD)MF_SOURCE_READER_FIRST_AUDIO_STREAM;
        if (FAILED(reader->GetNativeMediaType(audio_stream, 0, &a))) {
            printf("no video or audio stream\n");
            return 1;
        }
        GUID asub{};
        a->GetGUID(MF_MT_SUBTYPE, &asub);
        PROPVARIANT d;
        PropVariantInit(&d);
        reader->GetPresentationAttribute((DWORD)MF_SOURCE_READER_MEDIASOURCE, MF_PD_DURATION, &d);
        Com<IMFMediaType> pcm;
        MFCreateMediaType(&pcm);
        pcm->SetGUID(MF_MT_MAJOR_TYPE, MFMediaType_Audio);
        pcm->SetGUID(MF_MT_SUBTYPE, MFAudioFormat_PCM);
        HRESULT ph = reader->SetCurrentMediaType(audio_stream, nullptr, pcm);
        DWORD flags = 0;
        LONGLONG ts = 0;
        Com<IMFSample> s;
        HRESULT rh = SUCCEEDED(ph) ? reader->ReadSample(audio_stream, 0, nullptr, &flags, &ts, &s) : ph;
        printf("audio only: format tag 0x%04lx, duration %.2f s, decode to PCM: %s\n", asub.Data1,
               d.uhVal.QuadPart / 1e7, SUCCEEDED(rh) && s ? "ok" : "FAILED");
        return SUCCEEDED(rh) && s ? 0 : 1;
    }
    GUID sub{};
    native->GetGUID(MF_MT_SUBTYPE, &sub);
    UINT32 w = 0, h = 0, num = 0, den = 1;
    MFGetAttributeSize(native, MF_MT_FRAME_SIZE, &w, &h);
    MFGetAttributeRatio(native, MF_MT_FRAME_RATE, &num, &den);
    char cc[5];
    fourcc(sub, cc);
    PROPVARIANT dur;
    PropVariantInit(&dur);
    reader->GetPresentationAttribute((DWORD)MF_SOURCE_READER_MEDIASOURCE, MF_PD_DURATION, &dur);
    printf("video: %s %ux%u %.3f fps, duration %.2f s\n", cc, w, h, den ? (double)num / den : 0.0,
           dur.uhVal.QuadPart / 1e7);

    Com<IMFMediaType> audio;
    if (SUCCEEDED(reader->GetNativeMediaType((DWORD)MF_SOURCE_READER_FIRST_AUDIO_STREAM, 0, &audio))) {
        GUID asub{};
        audio->GetGUID(MF_MT_SUBTYPE, &asub);
        UINT32 rate = 0, ch = 0;
        audio->GetUINT32(MF_MT_AUDIO_SAMPLES_PER_SECOND, &rate);
        audio->GetUINT32(MF_MT_AUDIO_NUM_CHANNELS, &ch);
        printf("audio: format tag 0x%04lx, %u Hz, %u channels\n", asub.Data1, rate, ch);
    } else {
        printf("audio: none\n");
    }

    Com<IMFMediaType> rgb;
    MFCreateMediaType(&rgb);
    rgb->SetGUID(MF_MT_MAJOR_TYPE, MFMediaType_Video);
    rgb->SetGUID(MF_MT_SUBTYPE, MFVideoFormat_RGB32);
    hr = reader->SetCurrentMediaType(video, nullptr, rgb);
    if (FAILED(hr)) {
        fwprintf(stderr, L"decoder cannot produce RGB32 (0x%08lx)\n", hr);
        return 1;
    }
    Com<IMFMediaType> cur;
    reader->GetCurrentMediaType(video, &cur);
    MFGetAttributeSize(cur, MF_MT_FRAME_SIZE, &w, &h);
    INT32 stride = (INT32)MFGetAttributeUINT32(cur, MF_MT_DEFAULT_STRIDE, w * 4);
    GUID cur_sub{};
    cur->GetGUID(MF_MT_SUBTYPE, &cur_sub);
    UINT32 interlace = MFGetAttributeUINT32(cur, MF_MT_INTERLACE_MODE, 0);
    UINT32 nominal = MFGetAttributeUINT32(cur, MF_MT_VIDEO_NOMINAL_RANGE, 0);
    printf("output: subtype 0x%08lx (RGB32 = 0x00000016), %ux%u, stride %d, interlace mode %u, nominal range %u\n",
           cur_sub.Data1, w, h, stride, interlace, nominal);
    UINT32 native_interlace = MFGetAttributeUINT32(native, MF_MT_INTERLACE_MODE, 0);
    printf("native interlace mode %u (2 = progressive)\n", native_interlace);

    Com<IWICImagingFactory> wic;
    CoCreateInstance(CLSID_WICImagingFactory, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&wic));
    std::vector<BYTE> pixels((size_t)w * h * 4);

    for (int i = 3; i < argc; ++i) {
        LONGLONG target = (LONGLONG)(_wtof(argv[i]) * 1e7);
        PROPVARIANT pos;
        InitPropVariantFromInt64(target, &pos);
        reader->SetCurrentPosition(GUID_NULL, pos);
        PropVariantClear(&pos);
        bool saved = false;
        for (int n = 0; n < 2000 && !saved; ++n) {  // decode forward from the key frame to the target time
            DWORD flags = 0;
            LONGLONG ts = 0;
            Com<IMFSample> sample;
            if (FAILED(reader->ReadSample(video, 0, nullptr, &flags, &ts, &sample)) ||
                (flags & MF_SOURCE_READERF_ENDOFSTREAM))
                break;
            if (!sample || ts + 400000 < target)
                continue;
            Com<IMFMediaBuffer> buf;
            sample->ConvertToContiguousBuffer(&buf);
            BYTE *data = nullptr;
            DWORD len = 0;
            buf->Lock(&data, nullptr, &len);
            if (n == 0 || !saved)
                printf("  buffer %lu bytes (expected %u); first pixel BGRX %02x %02x %02x %02x, next %02x %02x %02x %02x\n",
                       len, w * h * 4, data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7]);
            UINT row = w * 4, abs_stride = (UINT)(stride < 0 ? -stride : stride);
            for (UINT y = 0; y < h && (size_t)(y + 1) * abs_stride <= len; ++y) {
                UINT src = stride < 0 ? h - 1 - y : y;  // bottom-up buffers are flipped
                memcpy(&pixels[(size_t)y * row], data + (size_t)src * abs_stride, row);
            }
            buf->Unlock();
            // Texture check: mean brightness change between neighbouring columns vs neighbouring rows (centre
            // region). Column >> row means real vertical stripes in the picture, not a viewer artefact.
            double dx = 0, dy = 0;
            UINT cnt = 0;
            auto luma = [&](UINT x, UINT y) {
                const BYTE *p = &pixels[((size_t)y * w + x) * 4];
                return 0.114 * p[0] + 0.587 * p[1] + 0.299 * p[2];
            };
            for (UINT y = h / 4; y < h * 3 / 4; ++y)
                for (UINT x = w / 4; x < w * 3 / 4; ++x, ++cnt) {
                    dx += fabs(luma(x + 1, y) - luma(x, y));
                    dy += fabs(luma(x, y + 1) - luma(x, y));
                }
            printf("  texture: mean |d/dx| %.2f, mean |d/dy| %.2f\n", dx / cnt, dy / cnt);
            wchar_t out[MAX_PATH];
            swprintf(out, MAX_PATH, L"%ls\\frame_%06.2f.png", argv[2], ts / 1e7);
            saved = write_png(wic, out, w, h, row, pixels.data());
            printf("frame at %.2f s -> %s\n", ts / 1e7, saved ? "saved" : "write failed");
        }
        if (!saved)
            printf("frame at %ls s: not decoded\n", argv[i]);
    }
    MFShutdown();
    return 0;
}
