package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// IMAGE_OPTIONAL_HEADER64 represents the optional header for 64-bit architecture.
type IMAGE_OPTIONAL_HEADER64 struct {
	Magic                       uint16
	MajorLinkerVersion          uint8
	MinorLinkerVersion          uint8
	SizeOfCode                  uint32
	SizeOfInitializedData       uint32
	SizeOfUninitializedData     uint32
	AddressOfEntryPoint         uint32
	BaseOfCode                  uint32
	ImageBase                   uint64
	SectionAlignment            uint32
	FileAlignment               uint32
	MajorOperatingSystemVersion uint16
	MinorOperatingSystemVersion uint16
	MajorImageVersion           uint16
	MinorImageVersion           uint16
	MajorSubsystemVersion       uint16
	MinorSubsystemVersion       uint16
	Win32VersionValue           uint32
	SizeOfImage                 uint32
	SizeOfHeaders               uint32
	CheckSum                    uint32
	Subsystem                   uint16
	DllCharacteristics          uint16
	SizeOfStackReserve          uint64
	SizeOfStackCommit           uint64
	SizeOfHeapReserve           uint64
	SizeOfHeapCommit            uint64
	LoaderFlags                 uint32
	NumberOfRvaAndSizes         uint32

	DataDirectory [16]IMAGE_DATA_DIRECTORY
}

// IMAGE_DATA_DIRECTORY represents a data directory entry.
type IMAGE_DATA_DIRECTORY struct {
	VirtualAddress uint32
	Size           uint32
}

// IMAGE_FILE_HEADER represents the file header in the IMAGE_NT_HEADERS structure.
type IMAGE_FILE_HEADER struct {
	Machine              uint16
	NumberOfSections     uint16
	TimeDateStamp        uint32
	PointerToSymbolTable uint32
	NumberOfSymbols      uint32
	SizeOfOptionalHeader uint16
	Characteristics      uint16
}

type IMAGE_NT_HEADERS64 struct {
	Signature      uint32
	FileHeader     IMAGE_FILE_HEADER
	OptionalHeader IMAGE_OPTIONAL_HEADER64
}
type IMAGE_SECTION_HEADER struct {
	Name                 [8]byte
	VirtualSize          uint32
	VirtualAddress       uint32
	SizeOfRawData        uint32
	PointerToRawData     uint32
	PointerToRelocations uint32
	PointerToLinenumbers uint32
	NumberOfRelocations  uint16
	NumberOfLinenumbers  uint16
	Characteristics      uint32
}

type BASE_RELOCATION_BLOCK struct {
	PageAddress uint32
	BlockSize   uint32
}

// BASE_RELOCATION_ENTRY represents the base relocation entry structure
type BASE_RELOCATION_ENTRY struct {
	OffsetType uint16 // Combined field for Offset and Type
}

// Offset extracts the Offset from the combined field
func (bre BASE_RELOCATION_ENTRY) Offset() uint16 {
	return bre.OffsetType & 0xFFF
}

// Type extracts the Type from the combined field
func (bre BASE_RELOCATION_ENTRY) Type() uint16 {
	return (bre.OffsetType >> 12) & 0xF
}

type IMAGE_IMPORT_DESCRIPTOR struct {
	Characteristics uint32
	TimeDateStamp   uint32
	ForwarderChain  uint32
	Name            uint32
	FirstThunk      uint32
}

func uintptrToBytes(ptr uintptr) []byte {
	// Create a pointer to the uintptr value
	ptrPtr := unsafe.Pointer(&ptr)

	// Convert the pointer to a byte slice
	byteSlice := make([]byte, unsafe.Sizeof(ptr))
	for i := 0; i < int(unsafe.Sizeof(ptr)); i++ {
		byteSlice[i] = *(*byte)(unsafe.Pointer(uintptr(ptrPtr) + uintptr(i)))
	}

	return byteSlice
}

const (
	IMAGE_DIRECTORY_ENTRY_IMPORT    = 0x1
	IMAGE_DIRECTORY_ENTRY_BASERELOC = 0x5
	DLL_PROCESS_ATTACH              = 0x1
)

func main() {
	fmt.Println()
	dllBytes, err := os.ReadFile("mydll.dll")
	if err != nil {
		log.Fatalf("Failed to open file %v", err)
	}
	dllPtr := uintptr(unsafe.Pointer(&dllBytes[0]))

	fmt.Printf("[+] DLL of size %d is loaded in memory at 0x%x\n", len(dllBytes), dllPtr)

	e_lfanew := *((*uint32)(unsafe.Pointer(dllPtr + 0x3c)))
	nt_header := (*IMAGE_NT_HEADERS64)(unsafe.Pointer(dllPtr + uintptr(e_lfanew)))

	dllBase, err := windows.VirtualAlloc(uintptr(nt_header.OptionalHeader.ImageBase),
		uintptr(nt_header.OptionalHeader.SizeOfImage),
		windows.MEM_RESERVE|windows.MEM_COMMIT,
		windows.PAGE_EXECUTE_READWRITE,
	)
	if err != nil {
		log.Fatalf("[!] VirtualAlloc Failed")
	}

	fmt.Printf("[+] Allocated address at 0x%x\n\n", dllBase)
	deltaImageBase := dllBase - uintptr(nt_header.OptionalHeader.ImageBase)
	var numberOfBytesWritten uintptr
	err = windows.WriteProcessMemory(windows.CurrentProcess(), dllBase, &dllBytes[0], uintptr(nt_header.OptionalHeader.SizeOfHeaders), &numberOfBytesWritten)
	if err != nil {
		log.Fatalf("[!] WriteProcessMemory Failed")
	}
	numberOfSections := int(nt_header.FileHeader.NumberOfSections)

	var sectionAddr uintptr
	sectionAddr = dllPtr + uintptr(e_lfanew) + unsafe.Sizeof(nt_header.Signature) + unsafe.Sizeof(nt_header.OptionalHeader) + unsafe.Sizeof(nt_header.FileHeader)

	for i := 0; i < numberOfSections; i++ {
		section := (*IMAGE_SECTION_HEADER)(unsafe.Pointer(sectionAddr))
		sectionDestination := dllBase + uintptr(section.VirtualAddress)
		sectionBytes := (*byte)(unsafe.Pointer(dllPtr + uintptr(section.PointerToRawData)))
		fmt.Printf("[+] Copying %d bytes from 0x%x -> 0x%x for section : %s", section.SizeOfRawData, dllPtr+uintptr(section.PointerToRawData), sectionDestination, windows.ByteSliceToString(section.Name[:]))

		err = windows.WriteProcessMemory(windows.CurrentProcess(), sectionDestination, sectionBytes, uintptr(section.SizeOfRawData), &numberOfBytesWritten)
		if err != nil {
			log.Fatalf("[!] WriteProcessMemory Failed: %v \n", err)
		}

		fmt.Printf("	... Bytes 0x%x/0x%x Written\n", section.SizeOfRawData, numberOfBytesWritten)
		if windows.ByteSliceToString(section.Name[:]) == ".text" {
			var oldprotect uint32
			err := windows.VirtualProtect(sectionDestination, uintptr(section.SizeOfRawData), windows.PAGE_EXECUTE_READ, &oldprotect)
			if err != nil {
				log.Fatalln("[ERROR] Failed to change memory permissions")
			}
		}
		sectionAddr += unsafe.Sizeof(*section)
	}
	fmt.Println()

	relocations := nt_header.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]
	relocation_table := uintptr(relocations.VirtualAddress) + dllBase
	fmt.Printf("[+] Relocation table Address: 0x%x\n\n", relocation_table)

	var relocations_processed int = 0
	for {

		relocation_block := *(*BASE_RELOCATION_BLOCK)(unsafe.Pointer(uintptr(relocation_table + uintptr(relocations_processed))))
		relocEntry := relocation_table + uintptr(relocations_processed) + 8
		if relocation_block.BlockSize == 0 && relocation_block.PageAddress == 0 {
			break
		}
		relocationsCount := (relocation_block.BlockSize - 8) / 2
		fmt.Printf("[+] PAGERVA : 0x%04x   Size: 0x%02x Entries Count: 0x%02x\n", relocation_block.PageAddress, relocation_block.BlockSize, relocationsCount)

		relocationEntries := make([]BASE_RELOCATION_ENTRY, relocationsCount)

		for i := 0; i < int(relocationsCount); i++ {
			relocationEntries[i] = *(*BASE_RELOCATION_ENTRY)(unsafe.Pointer(relocEntry + uintptr(i*2)))
		}
		for _, relocationEntry := range relocationEntries {
			if relocationEntry.Type() == 0 {
				continue
			}
			fmt.Printf("	--> Value: %X	Offset: %x\n", relocationEntry.OffsetType, relocationEntry.Offset())
			var size uintptr
			byteSlice := make([]byte, unsafe.Sizeof(size))
			relocationRVA := relocation_block.PageAddress + uint32(relocationEntry.Offset())

			err = windows.ReadProcessMemory(windows.CurrentProcess(), dllBase+uintptr(relocationRVA), &byteSlice[0], unsafe.Sizeof(size), nil)
			if err != nil {
				log.Fatalf("[ERROR] Failed to ReadProcessMemory")
			}
			addressToPatch := uintptr(binary.LittleEndian.Uint64(byteSlice))
			addressToPatch += deltaImageBase
			a2Patch := uintptrToBytes(addressToPatch)
			err = windows.WriteProcessMemory(windows.CurrentProcess(), dllBase+uintptr(relocationRVA), &a2Patch[0], uintptr(len(a2Patch)), nil)
			if err != nil {
				log.Fatalf("[ERROR] Failed to WriteProcessMemory")
			}

		}
		relocations_processed += int(relocation_block.BlockSize)

	}
	//time.Sleep(10 * time.Second)

	importsDirectory := nt_header.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]
	importDescriptorAddr := dllBase + uintptr(importsDirectory.VirtualAddress)
	fmt.Printf("[+] Import Descripton address: 0x%x\n\n", importDescriptorAddr)

	for {
		importDescriptor := *(*IMAGE_IMPORT_DESCRIPTOR)(unsafe.Pointer(importDescriptorAddr))
		if importDescriptor.Name == 0 {
			break
		}
		libraryName := uintptr(importDescriptor.Name) + dllBase
		dllName := windows.BytePtrToString((*byte)(unsafe.Pointer(libraryName)))
		fmt.Printf("[+] Importing DLL : %s\n", dllName)
		hLibrary, err := windows.LoadLibrary(dllName)
		if err != nil {
			log.Fatalln("[ERROR] LoadLibrary Failed")
		}
		addr := dllBase + uintptr(importDescriptor.FirstThunk)
		//char := dllBase + uintptr(importDescriptor.Characteristics)
		//fmt.Printf("First Thunk: 0%x\n", addr)
		//fmt.Printf("Chars: 0%x\n", char)
		for {
			thunk := *(*uint16)(unsafe.Pointer(addr))
			if thunk == 0 {
				break
			}
			functionNameAddr := dllBase + uintptr(thunk+2)

			functionName := windows.BytePtrToString((*byte)(unsafe.Pointer(functionNameAddr)))
			proc, err := windows.GetProcAddress(hLibrary, functionName)
			if err != nil {
				log.Fatalln("[ERROR] Failed to GetProcAddress")
			}
			fmt.Printf("	--> Importing Function %s -> Addr: 0x%x\n", functionName, proc)
			procBytes := uintptrToBytes(proc)
			// https://reverseengineering.stackexchange.com/questions/16870/import-table-vs-import-address-table
			var numberOfBytesWritten uintptr
			err = windows.WriteProcessMemory(windows.CurrentProcess(), addr, &procBytes[0], uintptr(len(procBytes)), &numberOfBytesWritten)
			if err != nil {
				log.Fatalln("[ERROR] Failed to WriteProcessMemory")
			}
			addr += 0x8

		}
		importDescriptorAddr += 0x14
	}
	//fmt.Printf("BreakPoint %x", dllBase+0x1251)
	//time.Sleep(time.Second * 10)
	syscall.SyscallN(dllBase+uintptr(nt_header.OptionalHeader.AddressOfEntryPoint), dllBase, DLL_PROCESS_ATTACH, 0)
	fmt.Println("[+] DLL function executed")
	err = windows.VirtualFree(dllBase, 0x0, windows.MEM_RELEASE)
	if err != nil {
		log.Fatalln("[ERROR] Failed to Free Memory")
	}
	fmt.Printf("[+] Freed Memory at 0x%x\n", dllBase)

}
