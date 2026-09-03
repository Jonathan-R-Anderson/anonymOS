A good approach is not to simply port Plan 9's syscalls. Instead, preserve the semantics that made Plan 9 elegant—"everything is a namespace" and "everything is accessed through a common interface"—while replacing files with typed objects.

The result is essentially:

Plan 9 + COM + QNX + Mach Ports + Capability Security + Object Kernel

Every kernel resource becomes an object with methods. Syscalls become operations on object handles (capabilities).

Object Handle

Everything is referenced through a capability.

typedef uint64_t ObjHandle;

The kernel validates every handle.

Objects include

Process
Thread
Domain
Window
Surface
NetworkSocket
Device
Timer
Event
Identity
Package
Volume
Pipe
Service
GPU Buffer
AI Model
Namespace
etc.
Object Management
CreateObject()

Create a new kernel object.

ObjHandle CreateObject(Type, Template)
DestroyObject()

Delete object.

CloneObject()

Copy object.

Supports

deep clone
snapshot
COW clone
OpenObject()

Equivalent of Plan9 open()

Obtains a capability to an object.

CloseObject()

Release capability.

DuplicateObject()

Equivalent of dup().

MoveObject()

Move object between namespaces.

LinkObject()

Equivalent of hard link.

Creates another reference.

UnlinkObject()

Remove reference.

RenameObject()

Rename.

LookupObject()

Lookup object by name.

EnumerateChildren()

Equivalent of reading directory.

Returns children.

GetParent()
GetRoot()
ResolvePath()

Equivalent of walk().

Namespace

Instead of filesystems

Everything lives inside object namespaces.

MountNamespace()

Plan9 mount()

BindNamespace()

Plan9 bind()

UnmountNamespace()
CreateNamespace()
DestroyNamespace()
AttachNamespace()
DetachNamespace()
EnumerateNamespace()
ImportNamespace()
ExportNamespace()
JoinNamespace()
LeaveNamespace()
Object Metadata
GetProperty()
SetProperty()
DeleteProperty()
ListProperties()
GetType()
GetClass()
GetPermissions()
SetPermissions()
GetOwner()
SetOwner()
GetACL()
SetACL()
QueryCapabilities()
SetCapabilityMask()
IPC

Plan9's best feature.

Instead of file descriptors

Everything uses object ports.

CreatePort()
ConnectPort()
DisconnectPort()
Send()
Receive()
Reply()
Call()

RPC

Broadcast()
PublishService()
DiscoverService()
Subscribe()
Unsubscribe()
CreateChannel()
DestroyChannel()
Wait()

Wait on object.

Signal()
Memory

Instead of mmap()

Objects represent memory.

AllocateMemory()
FreeMemory()
MapMemory()
UnmapMemory()
ProtectMemory()
ShareMemory()
PinMemory()
UnpinMemory()
FlushMemory()
SnapshotMemory()
CloneMemory()
Process

Plan9 had rfork()

Keep it.

CreateProcess()
DestroyProcess()
ExecObject()

Loads executable object.

ForkProcess()
RFork()

Plan9 semantics.

SpawnProcess()
WaitProcess()
KillProcess()
SuspendProcess()
ResumeProcess()
SetPriority()
GetPriority()
EnumerateProcesses()
GetCurrentProcess()
Thread
CreateThread()
ExitThread()
SuspendThread()
ResumeThread()
JoinThread()
EnumerateThreads()
SetAffinity()
Yield()
Scheduler
Sleep()
Wake()
Schedule()
SetSchedulingPolicy()
GetSchedulingPolicy()
Timer
CreateTimer()
StartTimer()
StopTimer()
ResetTimer()
WaitTimer()
QueryTime()

Equivalent to Plan9 nsec()

Events
CreateEvent()
TriggerEvent()
WaitEvent()
ResetEvent()
PollObjects()

Plan9 style multiplexing.

Networking

Instead of sockets being files

Sockets are objects.

CreateSocket()
Connect()
Listen()
Accept()
SendPacket()
ReceivePacket()
Shutdown()
SetSocketOption()
GetSocketOption()
ResolveAddress()
PublishEndpoint()
Devices

Devices become objects.

EnumerateDevices()
OpenDevice()
CloseDevice()
QueryDevice()
ConfigureDevice()
ResetDevice()
SuspendDevice()
ResumeDevice()
Graphics

Objects.

CreateWindow()
DestroyWindow()
CreateSurface()
PresentSurface()
CreateTexture()
CreateBuffer()
SubmitGPUCommand()
MapGPUBuffer()
Audio
CreateAudioStream()
PlayAudio()
RecordAudio()
StopAudio()
SetVolume()
Storage

Volumes become objects.

CreateVolume()
MountVolume()
UnmountVolume()
SnapshotVolume()
RollbackVolume()
VerifyVolume()
EncryptVolume()
DecryptVolume()
Security

Capability-first.

Authenticate()
Authorize()
CreateIdentity()
DestroyIdentity()
Login()
Logout()
Impersonate()
RevokeCapability()
GrantCapability()
SealObject()
VerifySignature()
Transactions

One feature Plan9 lacked.

BeginTransaction()
CommitTransaction()
RollbackTransaction()
Checkpoint()
Object Store

Since your OS already has an object store.

CommitObject()
SnapshotObject()
RollbackObject()
DiffObjects()
MergeObjects()
SerializeObject()
DeserializeObject()
ExportObject()
ImportObject()
Services
RegisterService()
UnregisterService()
LocateService()
StartService()
StopService()
AI Objects

Useful for your OS.

LoadModel()
ExecuteModel()
ReleaseModel()
StreamTokens()
System

Equivalent of Plan9 syscalls.

Shutdown()
Reboot()
Panic()
GetSystemInfo()
GetKernelVersion()
GetStatistics()
GetRandom()
LoadModule()
UnloadModule()
EnumerateModules()
Debug
DebugAttach()
DebugDetach()
ReadProcessMemory()
WriteProcessMemory()
SetBreakpoint()
ContinueProcess()
Plan 9 Compatibility Mapping

Rather than exposing raw Plan 9 file syscalls, preserve their intent with object-oriented equivalents:

Plan 9 syscall	Object syscall equivalent	Description
open	OpenObject	Open a capability to an object.
create	CreateObject	Create a new object instance.
close	CloseObject	Release an object capability.
read	InvokeMethod(Read)	Read from an object's data interface.
write	InvokeMethod(Write)	Write through an object's interface.
seek	SetCursor / InvokeMethod(Seek)	Adjust the object's logical cursor where applicable.
remove	DestroyObject	Delete an object.
stat	GetMetadata	Retrieve object metadata.
wstat	SetMetadata	Update object metadata.
bind	BindNamespace	Overlay or bind namespaces.
mount	MountNamespace	Attach a namespace provider.
unmount	UnmountNamespace	Detach a namespace.
walk	ResolvePath	Traverse an object namespace.
dup	DuplicateObject	Duplicate a capability.
pipe	CreatePipe	Create a bidirectional pipe object.
rfork	RFork	Plan 9-style process/resource cloning.
exec	ExecObject	Execute an executable object.
await	WaitProcess	Wait for child process completion.
notify	RegisterNotification	Register asynchronous event notifications.
noted	AcknowledgeNotification	Complete notification handling.
alarm	StartTimer	Schedule a timer event.
sleep	Sleep	Suspend execution for a duration.
brk	ResizeMemoryObject	Grow or shrink a process memory object.
segattach	MapMemory	Map a memory object into an address space.
segdetach	UnmapMemory	Remove a memory mapping.
segflush	FlushMemory	Flush memory mappings or caches.
One additional syscall to consider

To fully embrace an object-oriented kernel, introduce a universal method invocation primitive:

InvokeMethod(
    ObjHandle target,
    MethodID method,
    const void* input,
    size_t input_size,
    void* output,
    size_t* output_size
);

Every object advertises its supported methods through introspection (ListMethods, GetInterface, QueryCapabilities), allowing specialized operations to be invoked without creating hundreds of object-specific syscalls. The fixed syscall surface remains compact, while new object types and capabilities can be added over time without expanding the kernel ABI. This preserves Plan 9's simplicity while enabling a richer object model suitable for a modern capability-based operating system.
