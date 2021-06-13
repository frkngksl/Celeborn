.code
	ZwProtectVirtualMemoryArbitrary proc
			mov r10, rcx
			mov eax, 50h
			syscall
			ret
	ZwProtectVirtualMemoryArbitrary endp

	ZwOpenProcessArbitrary proc
			mov r10, rcx
			mov eax, 26h
			syscall
			ret
	ZwOpenProcessArbitrary endp
	
	ZwCloseArbitrary proc
			mov r10, rcx
			mov eax, 0Fh
			syscall
			ret
	ZwCloseArbitrary endp

	ZwWriteVirtualMemoryArbitrary proc
			mov r10, rcx
			mov eax, 3Ah
			syscall
			ret
	ZwWriteVirtualMemoryArbitrary endp

	; Why I can't see ZwCreateFile ?
	NtCreateFileArbitrary proc
		mov r10, rcx
		mov eax, 55h
		syscall
		ret
	NtCreateFileArbitrary endp

	NtCreateSectionArbitrary proc
		mov r10, rcx
		mov eax, 4Ah
		syscall
		ret
	NtCreateSectionArbitrary endp

	ZwMapViewOfSectionArbitrary proc
		mov r10, rcx
		mov eax, 28h
		syscall
		ret
	ZwMapViewOfSectionArbitrary endp

	;NtReadFileArbitrary proc
	;	mov r10, rcx
	;	mov eax, 06h
	;	syscall
	;	ret
	;NtReadFileArbitrary endp
end