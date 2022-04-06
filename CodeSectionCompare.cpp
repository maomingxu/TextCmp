// CodeSectionCompare.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//
#define UMDF_USING_NTSTATUS //该宏定义可以解决NTATUS winnt.H ntstatus.H 重定义的warning
#include <ntstatus.h>
#include <Windows.h>
#include <iostream>
#include <vector>
#include <string>
#include <fstream>
#include <psapi.h>
#include "header.h"
using namespace std;
wchar_t* AnsiToUnicode(const char* szStr)
{
    int nLen = MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, szStr, -1, NULL, 0);
    if (nLen == 0)
    {
        return NULL;
    }
    wchar_t* pResult = new wchar_t[nLen];
    MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, szStr, -1, pResult, nLen);
    return pResult;
}

//将宽字节wchar_t*转化为单字节char* 
inline char* UnicodeToAnsi(const wchar_t* szStr)
{
    int nLen = WideCharToMultiByte(CP_ACP, 0, szStr, -1, NULL, 0, NULL, NULL);
    if (nLen == 0)
    {
        return NULL;
    }
    char* pResult = new char[nLen];
    WideCharToMultiByte(CP_ACP, 0, szStr, -1, pResult, nLen, NULL, NULL);
    return pResult;
}

void CCheckTextSectionDiff::Dump2File(const char* pDumpFile,BYTE* p, UINT64 size)
{
    if (!p)
        return;

    fstream f(pDumpFile, ios::out);//供写使用，文件不存在则创建，存在则清空原内容
    for (UINT a = 0;a < size;a++)
        f << p[a];
    f.close();
}


bool  CCheckTextSectionDiff::CheckDiff(const BYTE* p1, const BYTE* p2, UINT64 size,DWORD Virtualoffset)
{
    if (!p1 || !p2) return false;

    bool bRet = false;
    for (UINT32 n = 0; n < size; ++n)
    {
        if (p1[n] != p2[n])
        {
            bool bInjected = false;
            int i = 1;
            while (p1[n + i] != p2[n + i])
            {
                i++;
            }
            
            bInjected = i > HOOK_DATA_LEN ? true : false;
            if (bInjected)
            {
                // dwHookedAddr.push_back((DWORD)&pTextCode[n]);
                printf("Mem:0x%x\n", Virtualoffset + n);
                printf("Mem_code:");
                for (int j = 0;j < i;j++)
                    printf("0x%x,", p1[n + j]);
                printf("\n");
                printf("local_code:");
                for (int j = 0;j < i;j++)
                    printf("0x%x,", p2[n + j]);
                printf("\n");
                n += i;

                bRet = true;
            }
           
        }
        else
        {
            continue;
        }
    }

    return bRet;
}



NTSTATUS CCheckTextSectionDiff::ReadFileTextCode()
{
    if (!m_bFuncsImport) return -1;
    //Get Local File information
    CHAR fileName[MAX_PATH] = { 0 };
    DWORD dwLen = MAX_PATH;
    
    NTSTATUS status = pfnQueryFullProcessImageNameA(m_hProc, 0, fileName, &dwLen);
    if (NT_SUCCESS(status))
    {
        m_pFileCode = GetTextCodeLocal(fileName, dwLen);
        Dump2File("d:\\localtxt", m_pFileCode, dwLen);
    }

    return status;
}

NTSTATUS CCheckTextSectionDiff::ReadFileTextCodeWow64()
{
    if (!m_bFuncsImport) return -1;
    //Get Local File information
    CHAR fileName[MAX_PATH] = { 0 };
    DWORD dwLen = MAX_PATH;
   
    NTSTATUS status = pfnQueryFullProcessImageNameA(m_hProc, 0, fileName, &dwLen);
    if (NT_SUCCESS(status))
    {
        m_pFileCode = GetTextCodeLocalWoW64(fileName,dwLen);
        Dump2File("d:\\local.txt", m_pFileCode, dwLen);
    }

    return status;
}

BYTE* CCheckTextSectionDiff::GetTextCodeLocal(CHAR * szExeFileName,DWORD &codeSize)
{
    if (!szExeFileName) return NULL;
    BYTE* pFile = NULL;
    HANDLE hFile = NULL;
    HANDLE hFileMap = NULL;
    char* lpbMapAddress = NULL;
    do
    {
        hFile = CreateFileA(szExeFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile == NULL)
        {
            break;
        }

        hFileMap = CreateFileMappingA(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
        if (hFileMap == NULL)
        {
            break;
        }

        DWORD dwFileSize = GetFileSize(hFile, NULL);
        lpbMapAddress = (char*)MapViewOfFile(hFileMap, FILE_MAP_READ, 0, 0, dwFileSize);
        if (lpbMapAddress == NULL)
        {
            break;
        }

        PIMAGE_DOS_HEADER pFileImageDosHeader = (PIMAGE_DOS_HEADER)lpbMapAddress;
        PIMAGE_NT_HEADERS pFileImageNtHeader = (PIMAGE_NT_HEADERS)(lpbMapAddress + pFileImageDosHeader->e_lfanew);
        PIMAGE_SECTION_HEADER pFileFirstSection = (PIMAGE_SECTION_HEADER)((char*)pFileImageNtHeader + sizeof(IMAGE_NT_HEADERS));

     
        DWORD_PTR dwEntry = pFileImageNtHeader->OptionalHeader.AddressOfEntryPoint;
        DWORD dwIndxe = 0;
        PIMAGE_SECTION_HEADER pSection = pFileFirstSection;
        while (dwIndxe < pFileImageNtHeader->FileHeader.NumberOfSections)
        {
            if (dwEntry >= pSection->VirtualAddress && dwEntry <= (pSection->VirtualAddress + pSection->SizeOfRawData))
            {
                pFile = (BYTE*)malloc(pSection->SizeOfRawData);
                if (pFile)
                {
                    memset(pFile, 0, pSection->SizeOfRawData);
                }
                memcpy(pFile, (BYTE*)lpbMapAddress + pSection->PointerToRawData, pSection->SizeOfRawData);
                codeSize = pSection->SizeOfRawData;
                break;
            }
            pSection++;
            dwIndxe++;
        }
    } while (false);
  
    if(hFile)
    CloseHandle(hFile);

    if (lpbMapAddress)
        UnmapViewOfFile(lpbMapAddress);

    if (hFileMap)
        CloseHandle(hFileMap);
    
    return (BYTE*)pFile;
}


BYTE* CCheckTextSectionDiff::GetTextCodeLocalWoW64(CHAR* szExeFileName, DWORD& codeSize)
{
    if (!szExeFileName) return NULL;
    BYTE* pFile = NULL;
    HANDLE hFile = NULL;
    HANDLE hFileMap = NULL;
    char* lpbMapAddress = NULL;
    do
    {
        hFile = CreateFileA(szExeFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile == NULL)
        {
            break;
        }

        hFileMap = CreateFileMappingA(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
        if (hFileMap == NULL)
        {
            break;
        }

        DWORD dwFileSize = GetFileSize(hFile, NULL);
        lpbMapAddress = (char*)MapViewOfFile(hFileMap, FILE_MAP_READ, 0, 0, dwFileSize);
        if (lpbMapAddress == NULL)
        {
            break;
        }

        PIMAGE_DOS_HEADER pFileImageDosHeader = (PIMAGE_DOS_HEADER)lpbMapAddress;
        PIMAGE_NT_HEADERS64 pFileImageNtHeader = (PIMAGE_NT_HEADERS64)(lpbMapAddress + pFileImageDosHeader->e_lfanew);
        PIMAGE_SECTION_HEADER pFileFirstSection = (PIMAGE_SECTION_HEADER)((char*)pFileImageNtHeader + sizeof(IMAGE_NT_HEADERS64));


        DWORD dwEntry = pFileImageNtHeader->OptionalHeader.AddressOfEntryPoint;
        if (dwEntry == 0)
        {
            dwEntry = pFileImageNtHeader->OptionalHeader.BaseOfCode;
        }
        DWORD dwIndxe = 0;
        PIMAGE_SECTION_HEADER pSection = pFileFirstSection;
        while (dwIndxe < pFileImageNtHeader->FileHeader.NumberOfSections)
        {
            if (dwEntry >= pSection->VirtualAddress && dwEntry <= (pSection->VirtualAddress + pSection->SizeOfRawData))
            {
                pFile = (BYTE*)malloc(pSection->SizeOfRawData);
                if (pFile)
                {
                    memset(pFile, 0, pSection->SizeOfRawData);
                }
                memcpy(pFile, (BYTE*)lpbMapAddress + pSection->PointerToRawData, pSection->SizeOfRawData);

                break;
            }
            pSection++;
            dwIndxe++;
        }
    } while (false);

    if (hFile)
        CloseHandle(hFile);

    if (lpbMapAddress)
        UnmapViewOfFile(lpbMapAddress);

    if (hFileMap)
        CloseHandle(hFileMap);

    return (BYTE*)pFile;
}
NTSTATUS CCheckTextSectionDiff::ReadMemTextCode()
{
    if (!m_bFuncsImport) return -1;
    PROCESS_BASIC_INFORMATION basicInfo;
    IMAGE_DOS_HEADER dosHeader;
    IMAGE_NT_HEADERS ntHeaders;
    NTSTATUS status;
    PVOID imageBaseAddress = NULL;
    
    if (m_hProc)
    {
        status = pfnNtQueryInformationProcess(m_hProc, 0, &basicInfo, sizeof(basicInfo), NULL);
 
        if (!status && basicInfo.PebBaseAddress)
        {
            if (pfnReadProcessMemory(m_hProc, PTR_ADD_OFFSET(basicInfo.PebBaseAddress, FIELD_OFFSET(PEB, ImageBaseAddress)), &imageBaseAddress, sizeof(PVOID), NULL))
            {
                BOOL bRet = pfnReadProcessMemory(m_hProc, imageBaseAddress, &dosHeader, sizeof(IMAGE_DOS_HEADER), NULL);
                if (bRet)
                {
                    bRet = pfnReadProcessMemory(m_hProc,PTR_ADD_OFFSET(imageBaseAddress, dosHeader.e_lfanew), &ntHeaders, sizeof(IMAGE_NT_HEADERS), NULL);
                    if (bRet)
                    {
                        if (ntHeaders.Signature != IMAGE_NT_SIGNATURE)
                        {
                            return STATUS_INVALID_IMAGE_FORMAT;
                        }

                        if (ntHeaders.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC &&
                            ntHeaders.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
                        {
                            return STATUS_INVALID_IMAGE_FORMAT;
                         }

                        DWORD ntHeadersSize = (SIZE_T)UFIELD_OFFSET(IMAGE_NT_HEADERS, OptionalHeader) +
                            ntHeaders.FileHeader.SizeOfOptionalHeader +
                            ntHeaders.FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER);
                        if (ntHeadersSize > 1024 * 1024) // 1 MB
                        {
                            return  STATUS_INVALID_IMAGE_FORMAT;
                        }

                        BYTE* pContent = (BYTE*)malloc(ntHeadersSize);
                        if (pContent)
                        {
                            memset(pContent, 0, ntHeadersSize);
                        }
                        bRet = pfnReadProcessMemory(m_hProc, PTR_ADD_OFFSET(imageBaseAddress, dosHeader.e_lfanew), pContent, ntHeadersSize, NULL);
                        if (!bRet)
                        {
                            return  -1;
                        }
                        PIMAGE_SECTION_HEADER pFileFirstSection = (PIMAGE_SECTION_HEADER)((char*)pContent + sizeof(IMAGE_NT_HEADERS));
                     
                        DWORD_PTR dwEntry = ntHeaders.OptionalHeader.AddressOfEntryPoint;
                        DWORD dwIndxe = 0;
                        PIMAGE_SECTION_HEADER pSection = pFileFirstSection;
                        while (dwIndxe < ntHeaders.FileHeader.NumberOfSections)
                        {
                            if (dwEntry >= pSection->VirtualAddress && dwEntry <= (pSection->VirtualAddress + pSection->SizeOfRawData))
                            {
                                m_MemCodeSize = Align(pSection->Misc.VirtualSize, ntHeaders.OptionalHeader.SectionAlignment);
                                m_pMemCode = (BYTE*)malloc(m_MemCodeSize);
                                if (m_pMemCode)
                                {
                                    memset(m_pMemCode, 0, m_MemCodeSize);
                                }
                                bRet = pfnReadProcessMemory(m_hProc, PTR_ADD_OFFSET(imageBaseAddress, pSection->VirtualAddress), m_pMemCode, m_MemCodeSize, NULL);
                                if (!bRet)
                                {
                                   return -2;
                                }
                           //     Dump2File("d:\\mem.txt", m_pMemCode, m_MemCodeSize);
                                
                                break;
                            }
                            pSection++;
                            dwIndxe++;
                        }
                                          
                        m_FileCodeSize = pSection->SizeOfRawData;
                        m_virtualOff = pSection->VirtualAddress ;

                        if (pContent)
                        {
                            free(pContent);
                            pContent = NULL;
                        }
                     
                    }
                }

            }

        }

       
    }

    return 0;
}


PEB64* g_peb64 = NULL;
NTSTATUS CCheckTextSectionDiff::ReadMemTextCodeWoW64()
{
    if (!m_bFuncsImport) return -1;
    _PROCESS_BASIC_INFORMATION_T<DWORD64> basicInfo = { 0 };
   
    NTSTATUS status;

    INT64 imageBaseAddress = 0;
   
    if (m_hProc)
    {
        status = pfnNtWowQueryInformationProcess64(m_hProc, 0, (INT64*)&basicInfo, sizeof(basicInfo), NULL);
        if (!status && basicInfo.PebBaseAddress)
        {
            g_peb64 = (PEB64*)malloc(sizeof(PEB64));
            if (g_peb64)
            {
                memset(g_peb64, 0, sizeof(PEB64));
                status = pfnNtReadProcessMemoryWoW64(m_hProc, (INT64)(basicInfo.PebBaseAddress), g_peb64, sizeof(PEB64), NULL);
                if (!NT_SUCCESS(status))
                {
                    printf("ReadPEB64 failed!\n");
                }
            }
                        
            if (pfnNtReadProcessMemoryWoW64(m_hProc, (INT64)PTR_ADD_OFFSET64(basicInfo.PebBaseAddress, FIELD_OFFSET64(PEB64, ImageBaseAddress)), &imageBaseAddress, sizeof(INT64), NULL)==STATUS_SUCCESS)
            {
                INT64 imageBase64 = *(INT64*)&imageBaseAddress;
                ReadMemTextCodeByBaseWow64(imageBase64,&m_pMemCode,m_MemCodeSize,m_FileCodeSize,m_virtualOff);
            }

        }

      
    }

    return 0;
}

NTSTATUS CCheckTextSectionDiff::ReadMemTextCodeByBase(DWORD imageBase, __inout BYTE** mem, __out DWORD& memSize, __out DWORD& fileCodeSize, __out DWORD& virtualOff)
{

    NTSTATUS status = 0;
    return status;
}

NTSTATUS CCheckTextSectionDiff::ReadMemTextCodeByBaseWow64(DWORD64 imageBase64,__inout BYTE **mem,__out DWORD &memSize,__out DWORD &fileCodeSize,__out DWORD &virtualOff)
{
    IMAGE_DOS_HEADER dosHeader;
    IMAGE_NT_HEADERS ntHeaders;

    NTSTATUS status;
    {
        status = pfnNtReadProcessMemoryWoW64(m_hProc, (INT64)imageBase64, &dosHeader, sizeof(IMAGE_DOS_HEADER), NULL);
        if (NT_SUCCESS(status))
        {
            status = pfnNtReadProcessMemoryWoW64(m_hProc, (INT64)PTR_ADD_OFFSET64(imageBase64, dosHeader.e_lfanew), &ntHeaders, sizeof(IMAGE_NT_HEADERS), NULL);
            if (NT_SUCCESS(status))
            {
                if (ntHeaders.Signature != IMAGE_NT_SIGNATURE)
                    return STATUS_INVALID_IMAGE_FORMAT;

                if (ntHeaders.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC &&
                    ntHeaders.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
                {
                    return STATUS_INVALID_IMAGE_FORMAT;
                }

                DWORD ntHeadersSize = (SIZE_T)UFIELD_OFFSET(IMAGE_NT_HEADERS, OptionalHeader) +
                    ntHeaders.FileHeader.SizeOfOptionalHeader +
                    ntHeaders.FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER);
                if (ntHeadersSize > 1024 * 1024) // 1 MB
                    return STATUS_INVALID_IMAGE_FORMAT;

                BYTE* pContent = (BYTE*)malloc(ntHeadersSize);
                if (pContent)
                {
                    memset(pContent, 0, ntHeadersSize);
                }
                status = pfnNtReadProcessMemoryWoW64(m_hProc, (INT64)PTR_ADD_OFFSET64(imageBase64, dosHeader.e_lfanew), pContent, ntHeadersSize, NULL);
                if (!NT_SUCCESS(status))
                    return -1;
                PIMAGE_SECTION_HEADER pFileFirstSection = (PIMAGE_SECTION_HEADER)((char*)pContent + sizeof(IMAGE_NT_HEADERS64));

                DWORD_PTR dwEntry = ntHeaders.OptionalHeader.AddressOfEntryPoint;
                if (dwEntry == 0)
                {
                    dwEntry = ntHeaders.OptionalHeader.BaseOfCode;
                }
                DWORD dwIndxe = 0;
                PIMAGE_SECTION_HEADER pSection = pFileFirstSection;
                while (dwIndxe < ntHeaders.FileHeader.NumberOfSections)
                {
                    if (dwEntry >= pSection->VirtualAddress && dwEntry <= (pSection->VirtualAddress + pSection->SizeOfRawData))
                    {
                        memSize = Align(pSection->Misc.VirtualSize, ntHeaders.OptionalHeader.SectionAlignment);
                        *mem = (BYTE*)malloc(memSize);
                        if (*mem)
                        {
                            memset(*mem, 0, memSize);
                        }
                        status = pfnNtReadProcessMemoryWoW64(m_hProc, (INT64)PTR_ADD_OFFSET64(imageBase64, pSection->VirtualAddress), *mem, memSize, NULL);
                        if (!NT_SUCCESS(status))
                            return -1;

                        break;
                    }
                    pSection++;
                    dwIndxe++;
                }

                fileCodeSize = pSection->SizeOfRawData;
                virtualOff = pSection->VirtualAddress;

                if (pContent)
                {
                    free(pContent);
                    pContent = NULL;
                }

            }
        }

    }

    return status;
}

void CCheckTextSectionDiff::getMem64(void* dstMem, DWORD64 srcMem, size_t sz)
{
    if ((nullptr == dstMem) || (0 == srcMem) || (0 == sz))
        return;
    if (dstMem)
    {
        memset((BYTE*)dstMem, 0, sz);
        NTSTATUS status = pfnNtReadProcessMemoryWoW64(m_hProc,srcMem, dstMem, sz, NULL);
        if (!NT_SUCCESS(status))
        {
            printf("getMem64 failed!\n");
        }
    }
    
}

DWORD64 CCheckTextSectionDiff::GetModuleHandle64(PEB64 *peb64,const wchar_t* lpModuleName)
{
    PEB_LDR_DATA64 ldr;
    getMem64(&ldr, peb64->Ldr, sizeof(PEB_LDR_DATA64));

    DWORD64 LastEntry = peb64->Ldr + offsetof(PEB_LDR_DATA64, InLoadOrderModuleList);
    LDR_DATA_TABLE_ENTRY64 head;
    head.InLoadOrderLinks.Flink = ldr.InLoadOrderModuleList.Flink;
 //   getMem64(&head, head.InLoadOrderLinks.Flink, sizeof(LDR_DATA_TABLE_ENTRY64)); //跳过第一个模块。exe
    do
    {
        getMem64(&head, head.InLoadOrderLinks.Flink, sizeof(LDR_DATA_TABLE_ENTRY64));
        if (head.DllBase == peb64->ImageBaseAddress)
            continue;
        wchar_t* tempBuf = (wchar_t*)malloc(head.BaseDllName.MaximumLength);
        if (nullptr == tempBuf)
            return 0;
      //  WATCH(tempBuf);
        getMem64(tempBuf, head.BaseDllName.Buffer, head.BaseDllName.MaximumLength);

       
        BYTE* pMemCode = nullptr;
        DWORD outMemSize = 0;
        BYTE* pFileCode = nullptr;
        DWORD dwFileCodeSize = 0;
        DWORD dwVirtualOff = 0;
        ReadMemTextCodeByBaseWow64(head.DllBase, &pMemCode, outMemSize, dwFileCodeSize, dwVirtualOff);

        PVOID pFullPathName = nullptr;
        ALLOC(head.FullDllName.MaximumLength, pFullPathName);
        getMem64(pFullPathName, head.FullDllName.Buffer, head.FullDllName.MaximumLength);
        
        pFileCode = GetTextCodeLocalWoW64(UnicodeToAnsi((wchar_t*)pFullPathName), dwFileCodeSize);
        bool bRet = CheckDiff(pMemCode,pFileCode, dwFileCodeSize, dwVirtualOff);
        if (bRet)
        {
            wprintf(L"Module:%s \n\n",tempBuf);
        }
        FREE(pMemCode);
        FREE(pFileCode);
        FREE(tempBuf);
        FREE(pFullPathName);
        //if (0 == _wcsicmp(lpModuleName, tempBuf))
        //    return head.DllBase;
    } while (head.InLoadOrderLinks.Flink != LastEntry);

    return 0;
}


int main(int argc,char* argv[])
{
    std::cout << "Hello World!\n";
    DWORD index = 0;
    NTSTATUS status;
    do
     {
        CCheckTextSectionDiff obj(atoi(argv[1]));

        printf("Check time=%d\n", index);
        status = obj.LoadTextCode();
        if(NT_SUCCESS(status))
        {
            BYTE* pMem = obj.MemCode();
            BYTE* pFile = obj.FileCode();
            DWORD size = obj.FileCodeSize();
            DWORD off = obj.VirtualOff();

            obj.CheckDiff(pMem, pFile, size, off);

        }
        if (g_peb64)
        {
            free(g_peb64);
            g_peb64 = NULL;
        }
       
    } while (false);
    
    getchar();

    return 1;
}

 