#pragma once
// Test-only control/metadata. Implementation contains no network/system commands.
void fakeCurlConfigure(const char*);
bool fakeCurlContinue();
const char* fakeCurlStats();
