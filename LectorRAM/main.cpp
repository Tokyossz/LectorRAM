#include <iostream>
#include <vector>
#include <string>
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <iomanip>
#include <fstream>
#include <algorithm>
#include <thread>
#include <mutex>
#include <regex>
#include <atomic>

struct ProcessInfo {
    DWORD pid;
    std::wstring name;
};

struct MemoryRegion {
    void* baseAddress;
    size_t size;
};

struct ScanResult {
    uintptr_t address;
    std::string type;
    std::string content;
    std::string moduleName;
};

std::mutex g_resultsMutex;
std::vector<ScanResult> g_allResults;
std::atomic<size_t> g_totalBytesScanned{0};
std::atomic<int> g_matchesCount{0};

void setColor(WORD color) {
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), color);
}

void printHeader() {
    setColor(11);
    std::cout << "############################################################" << std::endl;
    std::cout << "##                                                        ##" << std::endl;
    std::cout << "##        FORENSIC MEMORY ANALYZER - PRO v1.5             ##" << std::endl;
    std::cout << "##        Multi-threaded & Artifact Detection             ##" << std::endl;
    std::cout << "##                                                        ##" << std::endl;
    std::cout << "############################################################" << std::endl;
    setColor(7);
}

std::string getModuleNameFromAddress(HANDLE hProcess, uintptr_t address) {
    HMODULE hMods[1024];
    DWORD cbNeeded;
    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
            MODULEINFO mi;
            if (GetModuleInformation(hProcess, hMods[i], &mi, sizeof(mi))) {
                uintptr_t base = (uintptr_t)mi.lpBaseOfDll;
                if (address >= base && address < base + mi.SizeOfImage) {
                    wchar_t szModName[MAX_PATH];
                    if (GetModuleBaseNameW(hProcess, hMods[i], szModName, sizeof(szModName) / sizeof(wchar_t))) {
                        std::wstring ws(szModName);
                        return std::string(ws.begin(), ws.end());
                    }
                }
            }
        }
    }
    return "Unknown/Heap/Stack";
}

bool isReadable(const std::string& s) {
    if (s.length() < 4) return false;
    int alphanumeric = 0;
    for (char c : s) {
        if (isalnum(static_cast<unsigned char>(c)) || isspace(static_cast<unsigned char>(c)) || strchr(".:/?=&-_!@#$%", c)) 
            alphanumeric++;
    }
    return (alphanumeric > (int)(s.length() * 0.4));
}

void processBuffer(const std::vector<char>& buffer, uintptr_t baseAddr, HANDLE hProcess, const std::string& filter) {
    static const std::regex ipRegex(R"(\b(?:\d{1,3}\.){3}\d{1,3}\b)");

    auto logResult = [&](uintptr_t addr, std::string type, std::string content) {
        if (!filter.empty()) {
            std::string lowerContent = content;
            std::string lowerFilter = filter;
            std::transform(lowerContent.begin(), lowerContent.end(), lowerContent.begin(), ::tolower);
            std::transform(lowerFilter.begin(), lowerFilter.end(), lowerFilter.begin(), ::tolower);
            if (lowerContent.find(lowerFilter) == std::string::npos) return;
        }

        if (isReadable(content)) {
            ScanResult res;
            res.address = addr;
            res.type = type;
            res.content = content;
            res.moduleName = getModuleNameFromAddress(hProcess, addr);

            std::lock_guard<std::mutex> lock(g_resultsMutex);
            g_allResults.push_back(res);
            g_matchesCount++;
            
            setColor(10); std::cout << "[+] "; setColor(7);
            std::cout << "[0x" << std::hex << std::setw(12) << std::setfill('0') << addr << "] "
                      << std::setfill(' ') << std::setw(10) << type << " | "
                      << std::setw(15) << res.moduleName << " | " << content << std::dec << std::endl;
        }
    };

    std::string current;
    for (size_t i = 0; i < buffer.size(); ++i) {
        unsigned char c = (unsigned char)buffer[i];
        if (c >= 32 && c <= 126) current += buffer[i];
        else {
            if (current.length() >= 4) logResult(baseAddr + i - current.length(), "ASCII", current);
            current.clear();
        }
    }

    for (int offset = 0; offset <= 1; ++offset) {
        std::wstring wcurrent;
        for (size_t i = offset; i + 1 < buffer.size(); i += 2) {
            wchar_t wc = *reinterpret_cast<const wchar_t*>(&buffer[i]);
            if (wc >= 32 && wc <= 126) wcurrent += wc;
            else {
                if (wcurrent.length() >= 4) {
                    std::string conv(wcurrent.begin(), wcurrent.end());
                    logResult(baseAddr + i - (wcurrent.length() * 2), "UTF-16", conv);
                }
                wcurrent.clear();
            }
        }
    }
}

void workerThread(HANDLE hProcess, std::vector<MemoryRegion> regions, std::string filter) {
    for (const auto& region : regions) {
        std::vector<char> buffer(region.size);
        SIZE_T bytesRead;
        if (ReadProcessMemory(hProcess, region.baseAddress, buffer.data(), region.size, &bytesRead)) {
            processBuffer(buffer, (uintptr_t)region.baseAddress, hProcess, filter);
            g_totalBytesScanned += bytesRead;
        }
    }
}

void forensicScan(DWORD pid, const std::string& filter, const std::string& filename) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) {
        setColor(12); std::cerr << "[-] Error critico: Privilegios insuficientes para el PID " << pid << std::endl;
        setColor(7); return;
    }

    std::vector<MemoryRegion> allRegions;
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    MEMORY_BASIC_INFORMATION mbi;
    unsigned char* addr = (unsigned char*)si.lpMinimumApplicationAddress;

    while (addr < si.lpMaximumApplicationAddress) {
        if (VirtualQueryEx(hProcess, addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
            if (mbi.State == MEM_COMMIT && (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)) && !(mbi.Protect & PAGE_GUARD)) {
                allRegions.push_back({mbi.BaseAddress, mbi.RegionSize});
            }
            addr += mbi.RegionSize;
        } else addr += si.dwPageSize;
    }

    size_t numThreads = std::thread::hardware_concurrency();
    if (numThreads == 0) numThreads = 2;
    std::vector<std::thread> threads;
    std::vector<std::vector<MemoryRegion>> threadRegions(numThreads);

    for (size_t i = 0; i < allRegions.size(); ++i) {
        threadRegions[i % numThreads].push_back(allRegions[i]);
    }

    setColor(14);
    std::cout << "[*] Iniciando motor forense con " << numThreads << " hilos de ejecucion..." << std::endl;
    setColor(7);

    for (size_t i = 0; i < numThreads; ++i) {
        threads.emplace_back(workerThread, hProcess, threadRegions[i], filter);
    }

    for (auto& t : threads) t.join();

    if (!filename.empty()) {
        std::ofstream log(filename);
        log << "FORENSIC REPORT - PID: " << pid << "\n";
        log << "--------------------------------------\n";
        for (const auto& r : g_allResults) {
            log << "[0x" << std::hex << std::setw(12) << std::setfill('0') << r.address << "] "
                << std::setfill(' ') << std::setw(10) << r.type << " | "
                << std::setw(20) << r.moduleName << " | " << r.content << "\n";
        }
        log.close();
        setColor(10); std::cout << "\n[+] Reporte forense consolidado en: " << filename << std::endl;
    }

    std::cout << "\n--- Resumen de Analisis ---" << std::endl;
    std::cout << "Bytes procesados: " << (g_totalBytesScanned / (1024 * 1024)) << " MB" << std::endl;
    std::cout << "Artefactos encontrados: " << g_matchesCount << std::endl;
    setColor(7);

    CloseHandle(hProcess);
}

int main() {
    SetConsoleOutputCP(CP_UTF8);
    printHeader();

    std::vector<ProcessInfo> processes;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe32;
        pe32.dwSize = sizeof(pe32);
        if (Process32FirstW(hSnapshot, &pe32)) {
            do { processes.push_back({pe32.th32ProcessID, pe32.szExeFile}); } while (Process32NextW(hSnapshot, &pe32));
        }
        CloseHandle(hSnapshot);
    }

    for (size_t i = 0; i < processes.size(); ++i) {
        std::cout << "[" << std::setw(3) << i << "] PID: " << std::setw(6) << processes[i].pid << " - ";
        std::wcout << processes[i].name << std::endl;
    }

    size_t choice;
    std::cout << "\nSelecciona el indice del proceso para ANALISIS PRO: ";
    if (!(std::cin >> choice) || choice >= processes.size()) return 1;

    std::string filter, filename;
    std::cout << "Filtro IoC (ej: 'admin', Enter para saltar): ";
    std::cin.ignore(); std::getline(std::cin, filter);
    std::cout << "Nombre del reporte forense (ej: forensic.txt): ";
    std::getline(std::cin, filename);

    forensicScan(processes[choice].pid, filter, filename);

    std::cout << "\nPresiona Enter para cerrar el laboratorio...";
    std::cin.get();
    return 0;
}
