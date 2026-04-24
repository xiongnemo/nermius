//go:build windows

package service

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	windowsPresenceNone   = "none"
	windowsPresenceHello  = "windows-hello"
	windowsPresenceCredUI = "windows-credential-ui"

	windowsHelloMinBuild = 22000

	credUIWinEnumerateCurrentUser = 0x00000200

	errorCancelled           = 1223
	securityLogonInteractive = 2

	hresultOK                   = 0x00000000
	hresultFalse                = 0x00000001
	hresultPointer              = 0x80004003
	hresultNoInterface          = 0x80004002
	hresultRPCModeChanged       = 0x80010106
	asyncStatusStarted    int32 = 0
	asyncStatusCompleted  int32 = 1
	asyncStatusCanceled   int32 = 2
	asyncStatusError      int32 = 3

	userConsentVerifierAvailable = 0
	userConsentVerified          = 0
)

var (
	errWindowsCredentialCanceled = errors.New("Windows credential verification canceled")

	modKernel32 = windows.NewLazySystemDLL("kernel32.dll")
	modCombase  = windows.NewLazySystemDLL("combase.dll")
	modOle32    = windows.NewLazySystemDLL("ole32.dll")
	modCredui   = windows.NewLazySystemDLL("credui.dll")
	modAdvapi   = windows.NewLazySystemDLL("advapi32.dll")
	modSecur32  = windows.NewLazySystemDLL("secur32.dll")

	procGetConsoleWindow                  = modKernel32.NewProc("GetConsoleWindow")
	procRoInitialize                      = modCombase.NewProc("RoInitialize")
	procRoUninitialize                    = modCombase.NewProc("RoUninitialize")
	procRoGetActivationFactory            = modCombase.NewProc("RoGetActivationFactory")
	procWindowsCreateString               = modCombase.NewProc("WindowsCreateString")
	procWindowsDeleteString               = modCombase.NewProc("WindowsDeleteString")
	procCoTaskMemFree                     = modOle32.NewProc("CoTaskMemFree")
	procCredUIPromptForWindowsCredentials = modCredui.NewProc("CredUIPromptForWindowsCredentialsW")
	procLsaLogonUser                      = modSecur32.NewProc("LsaLogonUser")
	procLsaConnectUntrusted               = modSecur32.NewProc("LsaConnectUntrusted")
	procLsaDeregisterLogonProcess         = modSecur32.NewProc("LsaDeregisterLogonProcess")
	procLsaFreeReturnBuffer               = modSecur32.NewProc("LsaFreeReturnBuffer")
	procLsaNtStatusToWinError             = modAdvapi.NewProc("LsaNtStatusToWinError")
	procAllocateLocallyUniqueID           = modAdvapi.NewProc("AllocateLocallyUniqueId")

	windowsCurrentBuild = func() uint32 {
		return windows.RtlGetVersion().BuildNumber
	}
	windowsConsoleWindow = getConsoleWindow
	windowsHelloUsable   = realWindowsHelloUsable
	windowsHelloPrompt   = realWindowsHelloPrompt
	windowsCredUIUsable  = realWindowsCredUIUsable
	windowsCredUIPrompt  = realWindowsCredUIPrompt
)

type windowsPromptAuthorizer struct{}

type windowsPresenceBackend struct {
	kind string
	hwnd uintptr
}

type winCredUIInfo struct {
	size        uint32
	parent      uintptr
	messageText *uint16
	captionText *uint16
	banner      uintptr
}

type lsaString struct {
	length        uint16
	maximumLength uint16
	buffer        *byte
}

type lsaTokenSource struct {
	sourceName [8]byte
	sourceID   windows.LUID
}

type lsaQuotaLimits struct {
	pagedPoolLimit        uintptr
	nonPagedPoolLimit     uintptr
	minimumWorkingSetSize uintptr
	maximumWorkingSetSize uintptr
	pagefileLimit         uintptr
	timeLimit             int64
}

var (
	iidUserConsentVerifierStatics = windows.GUID{
		Data1: 0xaf4f3f91,
		Data2: 0x564c,
		Data3: 0x4ddc,
		Data4: [8]byte{0xb8, 0xb5, 0x97, 0x34, 0x47, 0x62, 0x7c, 0x65},
	}
	iidAsyncInfo = windows.GUID{
		Data1: 0x00000036,
		Data2: 0x0000,
		Data3: 0x0000,
		Data4: [8]byte{0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46},
	}
	iidUserConsentVerifierInterop = windows.GUID{
		Data1: 0x39e050c3,
		Data2: 0x4e74,
		Data3: 0x441a,
		Data4: [8]byte{0x8d, 0xc0, 0xb8, 0x11, 0x04, 0xdf, 0x94, 0x9c},
	}
	iidAsyncOperationUserConsentVerifierAvailability = windows.GUID{
		Data1: 0xddd384f3,
		Data2: 0xd818,
		Data3: 0x5d83,
		Data4: [8]byte{0xab, 0x4b, 0x32, 0x11, 0x9c, 0x28, 0x58, 0x7c},
	}
	iidAsyncOperationUserConsentVerificationResult = windows.GUID{
		Data1: 0xfd596ffd,
		Data2: 0x2318,
		Data3: 0x558f,
		Data4: [8]byte{0x9d, 0xbe, 0xd2, 0x1d, 0xf4, 0x37, 0x64, 0xa5},
	}
)

func (a *windowsPromptAuthorizer) Kind() string {
	return a.selectBackend(context.Background()).kind
}

func (a *windowsPromptAuthorizer) Available(ctx context.Context) (bool, string) {
	backend := a.selectBackend(ctx)
	switch backend.kind {
	case windowsPresenceHello:
		return true, "Windows Hello user consent"
	case windowsPresenceCredUI:
		return true, "Windows credential prompt"
	default:
		return false, "no Windows user-presence backend available"
	}
}

func (a *windowsPromptAuthorizer) UserPresence() bool {
	return a.selectBackend(context.Background()).kind != windowsPresenceNone
}

func (a *windowsPromptAuthorizer) Require(ctx context.Context, vaultID string, intent vaultAccessIntent) error {
	message := windowsPresenceMessage(vaultID, intent)
	backend := a.selectBackend(ctx)
	switch backend.kind {
	case windowsPresenceHello:
		if err := windowsHelloPrompt(ctx, message, backend.hwnd); err == nil {
			return nil
		}
		if !windowsCredUIUsable() {
			return errors.New("Windows Hello verification failed and credential prompt is unavailable")
		}
		return windowsCredUIPrompt(ctx, message, backend.hwnd)
	case windowsPresenceCredUI:
		return windowsCredUIPrompt(ctx, message, backend.hwnd)
	default:
		return errors.New("no Windows user-presence backend available")
	}
}

func (a *windowsPromptAuthorizer) selectBackend(ctx context.Context) windowsPresenceBackend {
	hwnd := windowsConsoleWindow()
	if windowsHelloUsable(ctx) {
		return windowsPresenceBackend{kind: windowsPresenceHello, hwnd: hwnd}
	}
	if windowsCredUIUsable() {
		return windowsPresenceBackend{kind: windowsPresenceCredUI, hwnd: hwnd}
	}
	return windowsPresenceBackend{kind: windowsPresenceNone, hwnd: hwnd}
}

func windowsPresenceMessage(vaultID string, intent vaultAccessIntent) string {
	shortID := vaultID
	if len(shortID) > 8 {
		shortID = shortID[:8]
	}
	return fmt.Sprintf("Authorize %s access to Nermius vault %s", intent, shortID)
}

func getConsoleWindow() uintptr {
	if err := procGetConsoleWindow.Find(); err != nil {
		return 0
	}
	hwnd, _, _ := procGetConsoleWindow.Call()
	return hwnd
}

func realWindowsHelloUsable(ctx context.Context) bool {
	if err := findWinRTProcs(); err != nil {
		return false
	}
	cleanup, err := winRTInitialize()
	if err != nil {
		return false
	}
	defer cleanup()
	if windowsHelloStaticsAvailable(ctx) {
		return true
	}
	if windowsCurrentBuild() < windowsHelloMinBuild || windowsConsoleWindow() == 0 {
		return false
	}
	factory, err := winRTActivationFactory("Windows.Security.Credentials.UI.UserConsentVerifier", &iidUserConsentVerifierInterop)
	if err != nil {
		return false
	}
	comRelease(factory)
	return true
}

func realWindowsHelloPrompt(ctx context.Context, message string, hwnd uintptr) error {
	if err := requestWindowsHelloStatics(ctx, message); err == nil {
		return nil
	}
	if hwnd == 0 {
		return errors.New("Windows Hello interop requires a parent window")
	}
	if err := findWinRTProcs(); err != nil {
		return err
	}
	cleanup, err := winRTInitialize()
	if err != nil {
		return err
	}
	defer cleanup()
	factory, err := winRTActivationFactory("Windows.Security.Credentials.UI.UserConsentVerifier", &iidUserConsentVerifierInterop)
	if err != nil {
		return err
	}
	defer comRelease(factory)
	messageString, releaseMessage, err := winRTString(message)
	if err != nil {
		return err
	}
	defer releaseMessage()
	var operation uintptr
	hr, _, _ := syscall.SyscallN(
		comMethod(factory, 6),
		factory,
		hwnd,
		messageString,
		uintptr(unsafe.Pointer(&iidAsyncOperationUserConsentVerificationResult)),
		uintptr(unsafe.Pointer(&operation)),
	)
	if failedHRESULT(hr) {
		return hresultError("RequestVerificationForWindowAsync", hr)
	}
	if operation == 0 {
		return errors.New("Windows Hello did not return a verification operation")
	}
	defer comRelease(operation)
	result, err := waitWinAsyncInt32(ctx, operation)
	if err != nil {
		return err
	}
	if result != userConsentVerified {
		return fmt.Errorf("Windows Hello verification was not accepted: result %d", result)
	}
	return nil
}

func windowsHelloStaticsAvailable(ctx context.Context) bool {
	factory, err := winRTActivationFactory("Windows.Security.Credentials.UI.UserConsentVerifier", &iidUserConsentVerifierStatics)
	if err != nil {
		return false
	}
	defer comRelease(factory)
	var operation uintptr
	hr, _, _ := syscall.SyscallN(
		comMethod(factory, 6),
		factory,
		uintptr(unsafe.Pointer(&operation)),
	)
	if failedHRESULT(hr) || operation == 0 {
		return false
	}
	defer comRelease(operation)
	result, err := waitWinAsyncInt32(ctx, operation)
	return err == nil && result == userConsentVerifierAvailable
}

func requestWindowsHelloStatics(ctx context.Context, message string) error {
	if err := findWinRTProcs(); err != nil {
		return err
	}
	cleanup, err := winRTInitialize()
	if err != nil {
		return err
	}
	defer cleanup()
	factory, err := winRTActivationFactory("Windows.Security.Credentials.UI.UserConsentVerifier", &iidUserConsentVerifierStatics)
	if err != nil {
		return err
	}
	defer comRelease(factory)
	messageString, releaseMessage, err := winRTString(message)
	if err != nil {
		return err
	}
	defer releaseMessage()
	var operation uintptr
	hr, _, _ := syscall.SyscallN(
		comMethod(factory, 7),
		factory,
		messageString,
		uintptr(unsafe.Pointer(&operation)),
	)
	if failedHRESULT(hr) {
		return hresultError("UserConsentVerifier.RequestVerificationAsync", hr)
	}
	if operation == 0 {
		return errors.New("UserConsentVerifier did not return a verification operation")
	}
	defer comRelease(operation)
	result, err := waitWinAsyncInt32(ctx, operation)
	if err != nil {
		return err
	}
	if result != userConsentVerified {
		return fmt.Errorf("Windows Hello verification was not accepted: result %d", result)
	}
	return nil
}

func findWinRTProcs() error {
	for _, proc := range []*windows.LazyProc{
		procRoInitialize,
		procRoUninitialize,
		procRoGetActivationFactory,
		procWindowsCreateString,
		procWindowsDeleteString,
	} {
		if err := proc.Find(); err != nil {
			return err
		}
	}
	return nil
}

func winRTInitialize() (func(), error) {
	hr, _, _ := procRoInitialize.Call(1)
	switch uint32(hr) {
	case hresultOK, hresultFalse:
		return func() { procRoUninitialize.Call() }, nil
	case hresultRPCModeChanged:
		return func() {}, nil
	default:
		if failedHRESULT(hr) {
			return nil, hresultError("RoInitialize", hr)
		}
		return func() {}, nil
	}
}

func winRTActivationFactory(className string, iid *windows.GUID) (uintptr, error) {
	classString, releaseClass, err := winRTString(className)
	if err != nil {
		return 0, err
	}
	defer releaseClass()
	var factory uintptr
	hr, _, _ := procRoGetActivationFactory.Call(
		classString,
		uintptr(unsafe.Pointer(iid)),
		uintptr(unsafe.Pointer(&factory)),
	)
	if failedHRESULT(hr) {
		return 0, hresultError("RoGetActivationFactory", hr)
	}
	if factory == 0 {
		return 0, errors.New("WinRT activation factory returned nil")
	}
	return factory, nil
}

func winRTString(value string) (uintptr, func(), error) {
	raw, err := windows.UTF16FromString(value)
	if err != nil {
		return 0, nil, err
	}
	var hstring uintptr
	hr, _, _ := procWindowsCreateString.Call(
		uintptr(unsafe.Pointer(&raw[0])),
		uintptr(len(raw)-1),
		uintptr(unsafe.Pointer(&hstring)),
	)
	if failedHRESULT(hr) {
		return 0, nil, hresultError("WindowsCreateString", hr)
	}
	return hstring, func() { procWindowsDeleteString.Call(hstring) }, nil
}

func waitWinAsyncInt32(ctx context.Context, operation uintptr) (int32, error) {
	var asyncInfo uintptr
	hr, _, _ := syscall.SyscallN(
		comMethod(operation, 0),
		operation,
		uintptr(unsafe.Pointer(&iidAsyncInfo)),
		uintptr(unsafe.Pointer(&asyncInfo)),
	)
	if failedHRESULT(hr) {
		return 0, hresultError("IAsyncOperation.QueryInterface(IAsyncInfo)", hr)
	}
	if asyncInfo == 0 {
		return 0, errors.New("IAsyncOperation returned nil IAsyncInfo")
	}
	defer comRelease(asyncInfo)
	deadline := time.After(2 * time.Minute)
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	status := asyncStatusStarted
	for status == asyncStatusStarted {
		hr, _, _ = syscall.SyscallN(
			comMethod(asyncInfo, 7),
			asyncInfo,
			uintptr(unsafe.Pointer(&status)),
		)
		if failedHRESULT(hr) {
			return 0, hresultError("IAsyncInfo.get_Status", hr)
		}
		if status != asyncStatusStarted {
			break
		}
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-deadline:
			return 0, errors.New("Windows verification timed out")
		case <-ticker.C:
		}
	}
	if status == asyncStatusCanceled {
		return 0, errors.New("Windows verification canceled")
	}
	if status == asyncStatusError {
		var asyncErr uintptr
		hr, _, _ = syscall.SyscallN(
			comMethod(asyncInfo, 8),
			asyncInfo,
			uintptr(unsafe.Pointer(&asyncErr)),
		)
		if failedHRESULT(hr) {
			return 0, hresultError("IAsyncInfo.get_ErrorCode", hr)
		}
		return 0, hresultError("Windows verification async operation", asyncErr)
	}
	if status != asyncStatusCompleted {
		return 0, fmt.Errorf("Windows verification did not complete successfully: async status %d", status)
	}
	var result int32
	hr, _, _ = syscall.SyscallN(
		comMethod(operation, 8),
		operation,
		uintptr(unsafe.Pointer(&result)),
	)
	if failedHRESULT(hr) {
		return 0, hresultError("IAsyncOperation.GetResults", hr)
	}
	return result, nil
}

func realWindowsCredUIUsable() bool {
	for _, proc := range []*windows.LazyProc{
		procCredUIPromptForWindowsCredentials,
		procLsaLogonUser,
		procLsaConnectUntrusted,
		procLsaDeregisterLogonProcess,
		procLsaFreeReturnBuffer,
		procLsaNtStatusToWinError,
		procAllocateLocallyUniqueID,
		procCoTaskMemFree,
	} {
		if err := proc.Find(); err != nil {
			return false
		}
	}
	return true
}

func realWindowsCredUIPrompt(ctx context.Context, message string, hwnd uintptr) error {
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		err := promptWindowsCredentialOnce(ctx, message, hwnd)
		if err == nil {
			return nil
		}
		if errors.Is(err, errWindowsCredentialCanceled) {
			return err
		}
		lastErr = err
	}
	if lastErr != nil {
		return lastErr
	}
	return errors.New("Windows credential verification failed")
}

func promptWindowsCredentialOnce(ctx context.Context, message string, hwnd uintptr) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	caption, err := windows.UTF16PtrFromString("Nermius vault authorization")
	if err != nil {
		return err
	}
	body, err := windows.UTF16PtrFromString(message)
	if err != nil {
		return err
	}
	info := winCredUIInfo{
		size:        uint32(unsafe.Sizeof(winCredUIInfo{})),
		parent:      hwnd,
		messageText: body,
		captionText: caption,
	}
	var authPackage uint32
	var outBuffer uintptr
	var outBufferSize uint32
	var save uint32
	flags := uint32(credUIWinEnumerateCurrentUser)
	ret, _, _ := procCredUIPromptForWindowsCredentials.Call(
		uintptr(unsafe.Pointer(&info)),
		0,
		uintptr(unsafe.Pointer(&authPackage)),
		0,
		0,
		uintptr(unsafe.Pointer(&outBuffer)),
		uintptr(unsafe.Pointer(&outBufferSize)),
		uintptr(unsafe.Pointer(&save)),
		uintptr(flags),
	)
	if ret == errorCancelled {
		return errWindowsCredentialCanceled
	}
	if ret != 0 {
		return windows.Errno(ret)
	}
	if outBuffer == 0 || outBufferSize == 0 {
		return errors.New("Windows credential prompt returned no credential buffer")
	}
	defer procCoTaskMemFree.Call(outBuffer)
	return validateWindowsCredentialBuffer(outBuffer, outBufferSize, authPackage)
}

func validateWindowsCredentialBuffer(authBuffer uintptr, authBufferSize uint32, authPackage uint32) error {
	var lsaHandle uintptr
	status, _, _ := procLsaConnectUntrusted.Call(uintptr(unsafe.Pointer(&lsaHandle)))
	if status != 0 {
		return ntStatusError("LsaConnectUntrusted", status)
	}
	defer procLsaDeregisterLogonProcess.Call(lsaHandle)

	origin, originBytes := newLSAString("Nermius")
	defer runtime.KeepAlive(originBytes)
	source, err := newLSATokenSource("Nermius")
	if err != nil {
		return err
	}
	var profile uintptr
	var profileSize uint32
	var logonID windows.LUID
	var token windows.Token
	var quotas lsaQuotaLimits
	var subStatus uintptr
	status, _, _ = procLsaLogonUser.Call(
		lsaHandle,
		uintptr(unsafe.Pointer(&origin)),
		uintptr(securityLogonInteractive),
		uintptr(authPackage),
		authBuffer,
		uintptr(authBufferSize),
		0,
		uintptr(unsafe.Pointer(&source)),
		uintptr(unsafe.Pointer(&profile)),
		uintptr(unsafe.Pointer(&profileSize)),
		uintptr(unsafe.Pointer(&logonID)),
		uintptr(unsafe.Pointer(&token)),
		uintptr(unsafe.Pointer(&quotas)),
		uintptr(unsafe.Pointer(&subStatus)),
	)
	if profile != 0 {
		defer procLsaFreeReturnBuffer.Call(profile)
	}
	if status != 0 {
		if subStatus != 0 {
			return ntStatusError("LsaLogonUser", subStatus)
		}
		return ntStatusError("LsaLogonUser", status)
	}
	if token == 0 {
		return errors.New("Windows credential verification returned no logon token")
	}
	defer token.Close()
	return requireCurrentWindowsUser(token)
}

func requireCurrentWindowsUser(token windows.Token) error {
	currentToken, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return err
	}
	defer currentToken.Close()
	currentUser, err := currentToken.GetTokenUser()
	if err != nil {
		return err
	}
	verifiedUser, err := token.GetTokenUser()
	if err != nil {
		return err
	}
	if !windows.EqualSid(currentUser.User.Sid, verifiedUser.User.Sid) {
		return errors.New("Windows credential verification did not authenticate the current user")
	}
	return nil
}

func newLSAString(value string) (lsaString, []byte) {
	raw := append([]byte(value), 0)
	return lsaString{
		length:        uint16(len(raw) - 1),
		maximumLength: uint16(len(raw)),
		buffer:        &raw[0],
	}, raw
}

func newLSATokenSource(name string) (lsaTokenSource, error) {
	var source lsaTokenSource
	copy(source.sourceName[:], []byte(name))
	ret, _, err := procAllocateLocallyUniqueID.Call(uintptr(unsafe.Pointer(&source.sourceID)))
	if ret == 0 {
		if err != syscall.Errno(0) {
			return source, err
		}
		return source, errors.New("AllocateLocallyUniqueId failed")
	}
	return source, nil
}

func ntStatusError(operation string, status uintptr) error {
	win32, _, _ := procLsaNtStatusToWinError.Call(status)
	if win32 != 0 {
		return fmt.Errorf("%s failed: %w", operation, windows.Errno(win32))
	}
	return fmt.Errorf("%s failed: NTSTATUS 0x%08x", operation, uint32(status))
}

func comRelease(object uintptr) {
	if object == 0 {
		return
	}
	syscall.SyscallN(comMethod(object, 2), object)
}

func comMethod(object uintptr, index uintptr) uintptr {
	vtbl := *(*uintptr)(unsafe.Pointer(object))
	return *(*uintptr)(unsafe.Pointer(vtbl + index*unsafe.Sizeof(uintptr(0))))
}

func failedHRESULT(hr uintptr) bool {
	return uint32(hr)&0x80000000 != 0
}

func hresultError(operation string, hr uintptr) error {
	return fmt.Errorf("%s failed: HRESULT 0x%08x", operation, uint32(hr))
}
