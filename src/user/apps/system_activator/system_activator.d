import std.stdio;
import std.json;
import std.file;
import std.path;
import std.process; // For future use if we call external build scripts

void main(string[] args) {
    writeln("WorldComputer System Activator (Simulation Mode)");
    writeln("================================================");

    string configFilePath = "worldcomputer_config/system.json";
    if (args.length > 1) {
        configFilePath = args[1];
    }

    if (!exists(configFilePath)) {
        stderr.writeln("Error: System configuration file '", configFilePath, "' not found.");
        return;
    }
    writeln("Loading system configuration from: ", configFilePath, "\n");

    try {
        auto jsonData = parseJSON(readText(configFilePath));

        // 1. Process System-Wide Settings
        if ("system" in jsonData) {
            auto systemConf = jsonData["system"];
            writeln("System Settings:");
            if ("hostname" in systemConf) {
                writeln("  - Would set hostname to: ", systemConf["hostname"].str);
            }
            if ("timezone" in systemConf) {
                writeln("  - Would set timezone to: ", systemConf["timezone"].str);
            }
            if ("kernelParams" in systemConf) {
                writeln("  - Would apply kernel parameters: ", systemConf["kernelParams"].str);
            }
            writeln("");
        }

        // 2. Process Recipes (Simulate ensuring they are built)
        if ("recipes" in jsonData && jsonData["recipes"].type == JSONType.array) {
            writeln("Recipe Management:");
            foreach (recipePathValue; jsonData["recipes"].array) {
                string recipePath = recipePathValue.str;
                writeln("  - Would ensure recipe is built: ", recipePath);
                // In a real system, this would trigger the build system if the recipe
                // or its specific version/hash isn't already in the immutable store.
                // For now, we can try to parse the recipe file for more info.
                if (exists(recipePath)) {
                    try {
                        auto recipeJson = parseJSON(readText(recipePath));
                        writeln("    - Recipe Name: ", recipeJson["name"].str, ", Version: ", recipeJson["version"].str);
                        if ("dependencies" in recipeJson && recipeJson["dependencies"].type == JSONType.array) {
                            foreach(dep; recipeJson["dependencies"].array) {
                                writeln("      - Depends on: ", dep.str);
                            }
                        }
                    } catch (JSONException e) {
                        writeln("    - Warning: Could not parse recipe file '", recipePath, "': ", e.msg);
                    }
                } else {
                    writeln("    - Warning: Recipe file '", recipePath, "' not found.");
                }
            }
            writeln("");
        }

        // 3. Process Services (Simulate enabling/disabling and configuring)
        if ("services" in jsonData && jsonData["services"].type == JSONType.array) {
            writeln("Service Configuration:");
            foreach (serviceConfValue; jsonData["services"].array) {
                auto serviceConf = serviceConfValue.object;
                string serviceName = serviceConf["name"].str;
                string serviceRecipe = serviceConf["recipe"].str;
                bool serviceEnabled = serviceConf["enabled"].boolean;

                writeln("  - Service: ", serviceName);
                writeln("    - Recipe: ", serviceRecipe);
                if (serviceEnabled) {
                    writeln("    - Status: Would be ENABLED");
                    // This is where the Plan 9 / Ubuntu Core concepts come in.
                    // The activator would:
                    //   1. Ensure the `serviceRecipe` is built (see above).
                    //   2. Create an isolated environment/namespace for the service.
                    //   3. Mount/bind the immutable recipe output into this namespace.
                    //   4. Generate service-specific config files (from `serviceConf["config"]`)
                    //      and make them available in the service's namespace.
                    //   5. Start the service.
                    if ("config" in serviceConf) {
                        writeln("    - Configuration: Would apply specific config: ", serviceConf["config"].toString());
                    }
                } else {
                    writeln("    - Status: Would be DISABLED");
                }
            }
            writeln("");
        }

        writeln("Activation simulation complete. No changes made to the system.");

    } catch (JSONException e) {
        stderr.writeln("JSON Parsing Error: ", e.msg);
        // .column is no longer available in JSONException.
        // e.msg often includes line and sometimes column information.
        // e.line is still available.
        stderr.writeln("  File: ", configFilePath, ", Line: ", e.line);
    } catch (FileException e) {
        stderr.writeln("File Error: ", e.msg);
    }
}