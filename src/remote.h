// Remote access relay (v3.9): the board opens an outbound, TLS-verified WebSocket to your
// Cloudflare Worker. Each browser request that reaches the Worker is replayed against this
// board's own web server (127.0.0.1:80) and the exact response is sent back. No port
// forwarding, no VPN, and the local web interface is untouched.
#pragma once
#include <Arduino.h>

void remoteBegin(const char *fwVersion);  // load settings, start the background task
bool remoteEnabled();
String remoteHost();                      // e.g. netdiag-remote.yourname.workers.dev
String remoteKey();                       // device key (also stored as a Cloudflare secret)
String remoteStatus();                    // human readable connection status
void remoteSet(bool enabled, const String &host);  // saves and reconnects
String remoteNewKey();                    // generates and saves a new random key
