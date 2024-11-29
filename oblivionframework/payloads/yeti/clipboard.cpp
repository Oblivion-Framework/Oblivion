#include <windows.h>
#include <iostream>
#include <string>

using namespace std;

string cliptext() {
    if (!OpenClipboard(nullptr)) {
        return "failed to open clipboard";
    }

    HANDLE hData = GetClipboardData(CF_TEXT);
    if  (hData == nullptr) {
        CloseClipboard();
        return "no text data on clipboard";
    }

    char* pszText = static_cast<char*>(GlobalLock(hData));
    if (pszText == nullptr) {
        CloseClipboard();
        return "failed to lock clipboard";
    }

    string text(pszText);
    GlobalUnlock(hData);
    CloseClipboard();

    return text;
}

int main() {
    cout << "Clipboard Monitoring started, Ctrl + C to stop.";

    string lastClipboardContent;

    while (true) {
        string currentClipboardContent = cliptext();

        if (currentClipboardContent != lastClipboardContent) {
            cout << "clipboard updated: " << currentClipboardContent;
            lastClipboardContent = currentClipboardContent;
        }

        Sleep(100);
    }

    return 0;
}