#include "stdafx.h"
#include "yara.h"



struct YaraRuleData {
    YR_COMPILER* compiler;
    YR_RULES* rules;
};

YaraRuleData yaraData;



std::vector<std::string> getFilesWithExtension(const std::string& directory, const std::string& extension)
{
    std::vector<std::string> files;
    std::string searchPattern = directory + "\\*" + extension;
    WIN32_FIND_DATAA findData;
    HANDLE hFind = FindFirstFileA(searchPattern.c_str(), &findData);
    if (hFind != INVALID_HANDLE_VALUE)
    {
        //std::ofstream logFile(directory + "\\yara.log", std::ios_base::app); 
        do
        {
            // Check if the file is not a directory
            if ((findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0)
            {
                // Add the file name to the list
                std::string fileName = findData.cFileName;
                std::string filePath = directory + "\\" + fileName;
                files.push_back(filePath);
                //logFile << filePath << std::endl;
            }
        } while (FindNextFileA(hFind, &findData));
        FindClose(hFind);
        //logFile.close();
    }
    return files;

}

YaraRuleData validateYaraRules()
{
    std::vector<std::string> yarFiles = getFilesWithExtension("C:\\programdata\\caseyamsi", ".yar");


    int initResult = yr_initialize();
    /*  I need to figure out how to return the error, but lets just hop this works for now.
    if (initResult != ERROR_SUCCESS) {
        logFile << "ERROR: Failed to initialize YARA library: " << initResult << std::endl;
        return;
    }
    */
    //    YaraRuleData LocalYaraRuleData;

        // initialize the compiler and rules pointers
    yaraData.compiler = new YR_COMPILER();
    yaraData.rules = new YR_RULES();

    //logFile << "PROCESSING YARA FILEs: " << std::endl;

    FILE* rulesFile = nullptr;

    yr_compiler_create(&yaraData.compiler);

    //looping through all yar riles
    for (const std::string& yarFile : yarFiles)
    {
        //open file
        fopen_s(&rulesFile, yarFile.c_str(), "r");
        if (rulesFile == nullptr)
        {
            // Should only be logging any failures.
            std::ofstream logFile("C:\\programdata\\caseyamsi\\yara.log", std::ios_base::app);

            logFile << "Failed to open YARA rules file: " << yarFile << std::endl;
            continue;
        }

        //compile rules
        int compileResult = yr_compiler_add_file(yaraData.compiler, rulesFile, nullptr, "C:\\programdata\\caseyamsi\\yara.log");
        if (compileResult != ERROR_SUCCESS)
        {
            // Should only be logging any failures.
            std::ofstream logFile("C:\\programdata\\caseyamsi\\yara.log", std::ios_base::app);

            logFile << "Failed to compile YARA rules file: " << yarFile << compileResult << std::endl;
            yr_compiler_destroy(yaraData.compiler);
            fclose(rulesFile);
            continue;
        }

        fclose(rulesFile);

    }
    //logFile << "FINISHED PROCESSING YARA FILES: " << std::endl;
    int loadResult = yr_compiler_get_rules(yaraData.compiler, &yaraData.rules);
    if (loadResult != ERROR_SUCCESS)
    {
        // Should only be logging any failures.
        std::ofstream logFile("C:\\programdata\\caseyamsi\\yara.log", std::ios_base::app);

        logFile << "Failed to load YARA rules file: " << &yaraData.rules << loadResult << std::endl;
        yr_compiler_destroy(yaraData.compiler);
    }
    else {
        //logFile << "Successfully to loaded YARA rules file: " << &YaraRuleData.rules << std::endl;
        YR_RULE* rule = &(yaraData.rules->rules_table[0]);
        //logFile << "Successfully to loaded YARA rule in Build: " << rule->identifier << std::endl;
        //}
    }
    return yaraData;

}


