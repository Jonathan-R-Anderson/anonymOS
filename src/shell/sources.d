module shell.sources;

enum immutable(char)[][] shellSourceFiles = [
    "src/shell/ast.d",
    "src/shell/executor.d",
    "src/shell/job.d",
    "src/shell/lexer.d",
    "src/shell/parser.d",
];

enum size_t shellSourceFileCount = shellSourceFiles.length;
