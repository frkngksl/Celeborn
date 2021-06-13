.code
	ZwProtectVirtualMemoryArbitrary proc
			mov r10, rcx
			mov eax, 50h
			syscall
			ret
	ZwProtectVirtualMemoryArbitrary endp

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