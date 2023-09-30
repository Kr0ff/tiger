#include "iat_camoflage.h"

BOOL camoflage_IAT() {
	
	BOOL res = FALSE;

    // APIs obtained from notepad.exe's imports
	unsigned __int64 api = GetUserDefaultUILanguage;
	api = MulDiv;
	api = CloseHandle;
	api = GetACP;
	api = WideCharToMultiByte;
	api = GetFocus;
	api = GetLastError;
    api = WaitForSingleObjectEx;
    api = GetTimeFormatW;
    api = GetDateFormatW;
    api = QueryPerformanceCounter;
    api = IsProcessorFeaturePresent;
    api = EnumFontsW;
    api = GetTextFaceW;

    int r = 0;
    int prev = 0;

    for (int i = 0; i < 512; i++) {
        for (int o = 0; o < 8196; o++) {
            if ((o % 2) == 0) {
                prev = o;

                if (o == prev) {
                    o++;
                }
                r = o;
                phibosachi(r);
            }
        }
    }

	res = TRUE;

	return res;
}

void phibosachi(int n)
{
    if (n < 1) {
        return;
    }

    // when number of terms is greater than 0
    int prev1 = 1;
    int prev2 = 0;

    // for loop to print fibonacci series
    for (int i = 1; i <= n; i++) {
        if (i > 2) {
            int num = prev1 + prev2;
            prev2 = prev1;
            prev1 = num;
            //printf("%d ", num);
        }

        // for first two terms
        if (i == 1) {
            //printf("%d ", prev2);
        }
        if (i == 2) {
            //printf("%d ", prev1);
        }
    }

    return;
}