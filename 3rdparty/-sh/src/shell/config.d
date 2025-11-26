module shell.config;

import std.file : exists, readText, thisExePath, getcwd, mkdirRecurse;
import std.json : JSONValue, parseJSON, JSON_TYPE;
import std.path : buildPath, dirName;
import std.process : environment;
import std.string : replace, startsWith;

private enum DEFAULT_PROMPT = "\033[1;32m{username}\033[0m@\033[1;35m{namespace}\033[0m " ~
                            "\033[1;34m{path}\033[0m " ~
                            "\033[1;33m[{permission}]\033[0m $ ";

struct PromptColours
{
    string username = "1;32";
    string path = "1;36";
    string namespaceId = "1;35";
    string permissionLevel = "1;33";
    string text = "0";
}

struct ShellPromptConfig
{
    string promptTemplate = DEFAULT_PROMPT;
    string namespaceId = "global";
    string permissionLevel = "user";
    string usernameOverride;
    PromptColours colours;
    string historyFile;
    string sourcePath;
}

private void setStringIfPresent(ref string target, JSONValue[string] obj, string key)
{
    if (auto value = key in obj)
    {
        if (value.type == JSON_TYPE.STRING)
        {
            target = value.str;
        }
    }
}

private void parseColours(ref PromptColours colours, JSONValue value)
{
    if (value.type != JSON_TYPE.OBJECT)
    {
        return;
    }

    auto obj = value.object;
    setStringIfPresent(colours.username, obj, "username");
    setStringIfPresent(colours.path, obj, "path");
    setStringIfPresent(colours.namespaceId, obj, "namespace");
    setStringIfPresent(colours.permissionLevel, obj, "permission");
    setStringIfPresent(colours.text, obj, "text");
}

private ShellPromptConfig applyConfig(ShellPromptConfig baseConfig, JSONValue json)
{
    if (json.type != JSON_TYPE.OBJECT)
    {
        return baseConfig;
    }

    auto obj = json.object;
    setStringIfPresent(baseConfig.promptTemplate, obj, "promptTemplate");
    setStringIfPresent(baseConfig.namespaceId, obj, "namespace");
    setStringIfPresent(baseConfig.permissionLevel, obj, "permission");
    setStringIfPresent(baseConfig.usernameOverride, obj, "username");
    setStringIfPresent(baseConfig.historyFile, obj, "historyFile");

    if (auto coloursPtr = "colours" in obj)
    {
        parseColours(baseConfig.colours, *coloursPtr);
    }
    else if (auto colorsPtr = "colors" in obj)
    {
        parseColours(baseConfig.colours, *colorsPtr);
    }

    return baseConfig;
}

private string[] candidateConfigPaths(string explicitPath)
{
    string[] candidates;

    if (explicitPath.length)
    {
        candidates ~= expandTilde(explicitPath);
    }

    auto envPath = environment.get("LFE_SH_CONFIG", "");
    if (envPath.length)
    {
        candidates ~= expandTilde(envPath);
    }

    try
    {
        auto cwdCandidate = buildPath(getcwd(), "prompt.json");
        candidates ~= cwdCandidate;
    }
    catch (Exception)
    {
        // ignore missing working directory
    }

    auto home = environment.get("HOME", "");
    if (home.length)
    {
        candidates ~= buildPath(home, ".lfe-sh", "config.json");
        candidates ~= buildPath(home, ".config", "lfe-sh", "config.json");
        candidates ~= buildPath(home, "prompt.json");
    }

    try
    {
        auto exe = thisExePath();
        if (exe.length)
        {
            auto exeDir = dirName(exe);
            if (exeDir.length)
            {
                candidates ~= buildPath(exeDir, "prompt.json");
                candidates ~= buildPath(exeDir, "config.json");
            }
        }
    }
    catch (Exception)
    {
        // Ignore failures retrieving executable path
    }

    candidates ~= "/etc/lfe-sh/config.json";
    candidates ~= "/etc/lfe-sh/prompt.json";

    string[string] seen;
    string[] uniqueCandidates;
    foreach (path; candidates)
    {
        if (path.length == 0)
        {
            continue;
        }
        if (path in seen)
        {
            continue;
        }
        seen[path] = path;
        uniqueCandidates ~= path;
    }

    return uniqueCandidates;
}

ShellPromptConfig loadShellConfig(string explicitPath = "")
{
    ShellPromptConfig config;

    foreach (path; candidateConfigPaths(explicitPath))
    {
        bool existsAtPath = false;
        try
        {
            existsAtPath = exists(path);
        }
        catch (Exception)
        {
            existsAtPath = false;
        }

        if (!existsAtPath)
        {
            continue;
        }

        try
        {
            auto contents = readText(path);
            auto parsed = parseJSON(contents);
            config = applyConfig(config, parsed);
            config.sourcePath = path;
            return config;
        }
        catch (Exception)
        {
            // ignore parse errors and try the next candidate
        }
    }

    return config;
}

private string applyColour(string value, string colour, string defaultColour)
{
    auto active = colour.length ? colour : defaultColour;
    if (active.length == 0 || active == "none")
    {
        return value;
    }

    return "\033[" ~ active ~ "m" ~ value ~ "\033[0m";
}

private string abbreviateHome(string path)
{
    auto home = environment.get("HOME", "");
    if (home.length && path.startsWith(home))
    {
        return "~" ~ path[home.length .. $];
    }
    return path;
}

private string expandTilde(string path)
{
    if (path.length && path[0] == '~')
    {
        auto home = environment.get("HOME", "");
        if (!home.length)
        {
            return path;
        }

        if (path.length == 1)
        {
            return home;
        }

        if (path.length >= 2 && (path[1] == '/' || path[1] == '\\'))
        {
            return buildPath(home, path[2 .. $]);
        }
    }

    return path;
}

string renderPrompt(const ShellPromptConfig config)
{
    auto user = config.usernameOverride.length
        ? config.usernameOverride
        : environment.get("USER", "user");

    auto nsValue = config.namespaceId.length
        ? config.namespaceId
        : environment.get("LFE_NAMESPACE", "global");

    auto permValue = config.permissionLevel.length
        ? config.permissionLevel
        : environment.get("LFE_PERMISSION", "user");

    string path;
    try
    {
        path = abbreviateHome(getcwd());
    }
    catch (Exception)
    {
        path = "?";
    }

    string prompt = config.promptTemplate.idup;
    prompt = replace(prompt ~ "", "{username}",  applyColour(user,     config.colours.username,       config.colours.text));
    prompt = replace(prompt ~ "", "{path}",      applyColour(path,     config.colours.path,           config.colours.text));
    prompt = replace(prompt ~ "", "{namespace}", applyColour(nsValue,  config.colours.namespaceId,    config.colours.text));
    prompt = replace(prompt ~ "", "{permission}",applyColour(permValue,config.colours.permissionLevel,config.colours.text));
 
    return prompt;
}

string resolveHistoryFile(const ShellPromptConfig config)
{
    if (config.historyFile.length)
    {
        return expandTilde(config.historyFile);
    }

    auto home = environment.get("HOME", "");
    if (!home.length)
    {
        return null;
    }

    return buildPath(home, ".lfe-sh_history");
}

void ensureHistoryDirectory(string historyPath)
{
    if (historyPath.length == 0)
    {
        return;
    }

    auto directory = dirName(historyPath);
    if (directory.length == 0)
    {
        return;
    }

    try
    {
        mkdirRecurse(directory);
    }
    catch (Exception)
    {
        // ignore directory creation failures
    }
}
