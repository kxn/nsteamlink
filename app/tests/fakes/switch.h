#pragma once
#include <stdint.h>
typedef uint32_t u32;
typedef uint32_t Result;
#define R_FAILED(r) ((r) != 0)
typedef enum { HidNpadIdType_No1 = 0, HidNpadIdType_Handheld = 0x20 } HidNpadIdType;
typedef enum {
    HidNpadStyleTag_NpadFullKey = 1,
    HidNpadStyleTag_NpadHandheld = 2,
    HidNpadStyleTag_NpadJoyDual = 4,
    HidNpadStyleTag_NpadJoyLeft = 8,
    HidNpadStyleTag_NpadJoyRight = 16
} HidNpadStyleTag;
typedef struct {
    u32 type_value;
} HidVibrationDeviceHandle;
typedef struct {
    float amp_low, freq_low, amp_high, freq_high;
} HidVibrationValue;
u32 hidGetNpadStyleSet(HidNpadIdType id);
Result hidInitializeVibrationDevices(HidVibrationDeviceHandle *, int, HidNpadIdType,
                                     HidNpadStyleTag);
Result hidSendVibrationValues(const HidVibrationDeviceHandle *, const HidVibrationValue *, int);
