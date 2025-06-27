
#include "pdf_parser.hpp"
#include "stealth_macros.hpp"
#include "utils.hpp"
#include "stealth_macros.hpp"
#include "secure_memory.hpp"
#include "stealth_macros.hpp"
#include "secure_exceptions.hpp"
#include "stealth_macros.hpp"
#include <iostream>
#include <fstream>
#include <cstdio>
#include "stealth_macros.hpp"
#include "stealth_macros.hpp"

class PDFVersionConverter {
public:
    static std::vector<uint8_t> convert_to_pdf14(const std::vector<uint8_t>& input_pdf) {
        try {
            // Parse the input PDF
            PDFParser parser;
            PDFStructure structure = parser.parse(input_pdf);
            
            // Complete silence enforcement - all debug output removed
            
            // If already PDF 1.4, return as-is
            if (structure.version == "1.4") {
                // Complete silence enforcement - all debug output removed
                return input_pdf;
            }
            
            // Convert structure to PDF 1.4
            structure.version = "1.4";
            
            // Remove modern PDF features that aren't compatible with 1.4
            remove_modern_features(structure);
            
            // Rebuild the PDF with 1.4 compatibility
            std::vector<uint8_t> output = rebuild_pdf_14(structure);
            
            // Complete silence enforcement - all debug output removed
            return output;
            
        } catch (const std::exception& e) {
            // Complete silence enforcement - all error output removed
            throw;
        }
    }
    
    static bool convert_file(const std::string& input_path, const std::string& output_path) {
        try {
            // Read input file
            // SECURITY FIX: Safe file opening with proper error handling
            std::ifstream file(input_path, std::ios::binary);
            if (!file.is_open()) {
                // Complete silence enforcement - all error output removed
                return false;
            }
            
            std::vector<uint8_t> input_data((std::istreambuf_iterator<char>(file)),
                                          std::istreambuf_iterator<char>());
            file.close();
            
            // Convert to PDF 1.4
            std::vector<uint8_t> output_data = convert_to_pdf14(input_data);
            
            // Write output file
            std::ofstream output_file(output_path, std::ios::binary);
            if (!output_file.is_open()) {
                // Complete silence enforcement - all error output removed
                return false;
            }
            
            output_file.write(reinterpret_cast<const char*>(output_data.data()), output_data.size());
            output_file.close();
            
            // Complete silence enforcement - all debug output removed
            return true;
            
        } catch (const std::exception& e) {
            // Complete silence enforcement - all error output removed
            return false;
        }
    }

private:
    static void remove_modern_features(PDFStructure& structure) {
        // Remove PDF 1.5+ features that aren't compatible with 1.4
        
        // Remove object streams (PDF 1.5+)
        auto it = std::remove_if(structure.objects.begin(), structure.objects.end(),
            [](const PDFObject& obj) {
                auto type_it = obj.dictionary.find("/Type");
                return type_it != obj.dictionary.end() && type_it->second == "/ObjStm";
            });
        structure.objects.erase(it, structure.objects.end());
        
        // Remove cross-reference streams
        it = std::remove_if(structure.objects.begin(), structure.objects.end(),
            [](const PDFObject& obj) {
                auto type_it = obj.dictionary.find("/Type");
                return type_it != obj.dictionary.end() && type_it->second == "/XRef";
            });
        structure.objects.erase(it, structure.objects.end());
        
        // Remove optional content (PDF 1.5+)
        for (auto& obj : structure.objects) {
            obj.dictionary.erase("/OCProperties");
            obj.dictionary.erase("/OCGs");
            obj.dictionary.erase("/OCMDs");
        }
        
        // Ensure trailer doesn't reference removed features
        structure.trailer.dictionary.erase("/XRefStm");
        
        // Complete silence enforcement - all debug output removed
    }
    
    static std::vector<uint8_t> rebuild_pdf_14(const PDFStructure& structure) {
        std::vector<uint8_t> output;
        
        // Write PDF 1.4 header
        std::string header = "%PDF-1.4\n";
        output.insert(output.end(), header.begin(), header.end());
        
        // Track object offsets for xref table
        std::map<int, size_t> object_offsets;
        
        // Write objects
        for (const auto& obj : structure.objects) {
            object_offsets[obj.number] = output.size();
            
            // Write object header
            std::string obj_header = std::to_string(obj.number) + " " + 
                                   std::to_string(obj.generation) + " obj\n";
            output.insert(output.end(), obj_header.begin(), obj_header.end());
            
            // Write dictionary if present
            if (!obj.dictionary.empty()) {
                std::string dict_str = "<<\n";
                for (const auto& entry : obj.dictionary) {
                    dict_str += entry.first + " " + entry.second + "\n";
                }
                dict_str += ">>\n";
                output.insert(output.end(), dict_str.begin(), dict_str.end());
            }
            
            // Write stream if present
            if (obj.has_stream && !obj.stream_data.empty()) {
                std::string stream_start = "stream\n";
                output.insert(output.end(), stream_start.begin(), stream_start.end());
                output.insert(output.end(), obj.stream_data.begin(), obj.stream_data.end());
                std::string stream_end = "\nendstream\n";
                output.insert(output.end(), stream_end.begin(), stream_end.end());
            }
            
            // Write object footer
            std::string obj_footer = "endobj\n";
            output.insert(output.end(), obj_footer.begin(), obj_footer.end());
        }
        
        // Write xref table
        size_t xref_offset = output.size();
        std::string xref_header = "xref\n0 " + std::to_string(object_offsets.size() + 1) + "\n";
        output.insert(output.end(), xref_header.begin(), xref_header.end());
        
        // Write xref entries
        std::string xref_entry = "0000000000 65535 f \n";
        output.insert(output.end(), xref_entry.begin(), xref_entry.end());
        
        for (const auto& offset_pair : object_offsets) {
            char entry[21];
            // SECURITY FIX: Replace unsafe sprintf with safe snprintf
            if (snprintf(entry, sizeof(entry), "%010zu 00000 n \n", offset_pair.second) >= sizeof(entry)) {
                throw SecureExceptions::SecurityViolationException("Buffer overflow prevented in xref entry formatting");
            }
            output.insert(output.end(), entry, entry + 20);
        }
        
        // Write trailer
        std::string trailer_str = "trailer\n<<\n/Size " + 
                                std::to_string(object_offsets.size() + 1) + "\n";
        
        for (const auto& entry : structure.trailer.dictionary) {
            if (entry.first != "/Size") {
                trailer_str += entry.first + " " + entry.second + "\n";
            }
        }
        trailer_str += ">>\nstartxref\n" + std::to_string(xref_offset) + "\n%%EOF\n";
        output.insert(output.end(), trailer_str.begin(), trailer_str.end());
        
        return output;
    }
};

// Command line interface
int main(int argc, char* argv[]) {
    if (argc != 3) {
        // Complete silence enforcement - all debug output removed
        // Complete silence enforcement - all debug output removed
        return 1;
    }
    
    std::string input_file = argv[1];
    std::string output_file = argv[2];
    
    // Complete silence enforcement - all debug output removed
    
    if (PDFVersionConverter::convert_file(input_file, output_file)) {
        // Complete silence enforcement - all debug output removed
        return 0;
    } else {
        // Complete silence enforcement - all debug output removed
        return 1;
    }
}
