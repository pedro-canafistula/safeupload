/* Prototype-only Inspector transport through the service-owned filter port.
 * Explicit opt-in; never fall back from a failed real driver connection.
 * The endpoint validates an independent control allowlist and requires SYSTEM.
 */
#if defined(SAFEUPLOAD_STAGING_PROTOTYPE) && SAFEUPLOAD_STAGING_PROTOTYPE
#define SU_PROOF_MAGIC 0x46505553u
#define SU_PROOF_REQUEST_MAX 4096u
#define SU_PROOF_REPLY_MAX 54664u
static HANDLE SuProofPort = NULL;

static BOOL SuProofSystemServer(HANDLE pipe)
{
    ULONG pid = 0;
    HANDLE process = NULL, token = NULL;
    BYTE storage[512];
    DWORD bytes = 0;
    BOOL trusted = FALSE;
    if (!GetNamedPipeServerProcessId(pipe, &pid) || pid == 0) return FALSE;
    process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (process == NULL) goto Done;
    if (!OpenProcessToken(process, TOKEN_QUERY, &token)) goto Done;
    if (!GetTokenInformation(token, TokenUser, storage, sizeof(storage), &bytes)) goto Done;
    trusted = IsWellKnownSid(((TOKEN_USER*)storage)->User.Sid, WinLocalSystemSid);
Done:
    if (token != NULL) CloseHandle(token);
    if (process != NULL) CloseHandle(process);
    return trusted;
}

static BOOL SuProofIo(HANDLE pipe, BOOL writing, BYTE* bytes, DWORD length, ULONGLONG deadline)
{
    DWORD done = 0;
    while (done < length) {
        OVERLAPPED operation;
        DWORD transferred = 0, error = ERROR_SUCCESS;
        BOOL ok;
        ULONGLONG now = GetTickCount64();
        if (now >= deadline) { SetLastError(ERROR_TIMEOUT); return FALSE; }
        ZeroMemory(&operation, sizeof(operation));
        operation.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
        if (operation.hEvent == NULL) return FALSE;
        ok = writing ? WriteFile(pipe, bytes + done, length - done, &transferred, &operation)
                     : ReadFile(pipe, bytes + done, length - done, &transferred, &operation);
        if (!ok) {
            error = GetLastError();
            if (error == ERROR_IO_PENDING) {
                DWORD wait = WaitForSingleObject(operation.hEvent, (DWORD)(deadline - now));
                if (wait == WAIT_OBJECT_0) {
                    ok = GetOverlappedResult(pipe, &operation, &transferred, FALSE);
                    if (!ok) error = GetLastError();
                } else {
                    /* Keep OVERLAPPED storage alive until cancellation completes. */
                    CancelIoEx(pipe, &operation);
                    (void)GetOverlappedResult(pipe, &operation, &transferred, TRUE);
                    error = wait == WAIT_TIMEOUT ? ERROR_TIMEOUT : ERROR_OPERATION_ABORTED;
                    ok = FALSE;
                }
            }
        }
        CloseHandle(operation.hEvent);
        if (!ok || transferred == 0 || transferred > length - done) {
            SetLastError(!ok ? error : ERROR_INVALID_DATA); return FALSE;
        }
        done += transferred;
    }
    return TRUE;
}

static HRESULT SuProofConnect(LPCWSTR name, DWORD options, LPVOID context, WORD contextSize,
    LPSECURITY_ATTRIBUTES attributes, HANDLE* port)
{
    WCHAR enabled[2];
    if (GetEnvironmentVariableW(L"SAFEUPLOAD_STAGED_PROOF_PROXY", enabled, ARRAYSIZE(enabled)) != 1 || enabled[0] != L'1')
        return FilterConnectCommunicationPort(name, options, context, contextSize, attributes, port);
    if (port == NULL || wcscmp(name, SAFEUPLOAD_PORT_NAME) != 0 || options != 0 || context != NULL || contextSize != 0 || attributes != NULL)
        return E_INVALIDARG;
    /* A real owned handle makes the Inspector's existing CloseHandle valid. */
    SuProofPort = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (SuProofPort == NULL) return HRESULT_FROM_WIN32(GetLastError());
    *port = SuProofPort;
    return S_OK;
}

static HRESULT SuProofSend(HANDLE port, LPVOID input, DWORD inputBytes, LPVOID output,
    DWORD outputBytes, LPDWORD returned)
{
    HANDLE pipe = INVALID_HANDLE_VALUE;
    BYTE request[4 + SU_PROOF_REQUEST_MAX], reply[12];
    DWORD bodyBytes;
    HRESULT hr = E_INVALIDARG;
    ULONGLONG deadline;
    if (port != SuProofPort || port == NULL)
        return FilterSendMessage(port, input, inputBytes, output, outputBytes, returned);
    if (returned == NULL) return E_INVALIDARG;
    *returned = 0;
    if (input == NULL || inputBytes < 16 || inputBytes > SU_PROOF_REQUEST_MAX - 64 ||
        outputBytes > SU_PROOF_REPLY_MAX || (outputBytes != 0 && output == NULL)) return E_INVALIDARG;
    bodyBytes = 64 + inputBytes;
    ZeroMemory(request, sizeof(request));
    CopyMemory(request, &bodyBytes, 4);
    { DWORD magic = SU_PROOF_MAGIC; CopyMemory(request + 4, &magic, 4); }
    CopyMemory(request + 8, &outputBytes, 4);
    CopyMemory(request + 12, &inputBytes, 4);
    CopyMemory(request + 68, input, inputBytes);
    pipe = CreateFileW(L"\\\\.\\pipe\\SafeUploadAdmissionEvidence.Capture", GENERIC_READ | GENERIC_WRITE,
        0, NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, NULL);
    if (pipe == INVALID_HANDLE_VALUE) return HRESULT_FROM_WIN32(GetLastError());
    if (!SuProofSystemServer(pipe)) { hr = E_ACCESSDENIED; goto Done; }
    deadline = GetTickCount64() + 10000;
    if (!SuProofIo(pipe, TRUE, request, 4 + bodyBytes, deadline) ||
        !SuProofIo(pipe, FALSE, reply, sizeof(reply), deadline)) {
        hr = HRESULT_FROM_WIN32(GetLastError()); goto Done;
    }
    { DWORD magic, count; HRESULT serviceHr;
      CopyMemory(&magic, reply, 4); CopyMemory(&serviceHr, reply + 4, 4); CopyMemory(&count, reply + 8, 4);
      if (magic != SU_PROOF_MAGIC || (FAILED(serviceHr) && count != 0) ||
          (SUCCEEDED(serviceHr) && (serviceHr != S_OK || count != outputBytes))) { hr = E_FAIL; goto Done; }
      if (FAILED(serviceHr)) { hr = serviceHr; goto Done; }
      if (count != 0 && !SuProofIo(pipe, FALSE, (BYTE*)output, count, deadline)) {
          hr = HRESULT_FROM_WIN32(GetLastError()); goto Done;
      }
      *returned = count; hr = S_OK;
    }
Done:
    CloseHandle(pipe);
    return hr;
}
#define FilterConnectCommunicationPort SuProofConnect
#define FilterSendMessage SuProofSend
#endif
