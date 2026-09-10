"""
Tree-sitter based multi-language parser for KernelSpy Scanner.
Provides unified Concrete Syntax Tree (CST) parsing for 30+ languages.
"""
import os
from typing import Optional, Dict, List, Tuple
from dataclasses import dataclass, field

try:
    import tree_sitter
    from tree_sitter import Language, Parser
    TREE_SITTER_AVAILABLE = True
except ImportError:
    TREE_SITTER_AVAILABLE = False

try:
    import tree_sitter_python
    import tree_sitter_javascript
    import tree_sitter_typescript
    import tree_sitter_java
    import tree_sitter_go
    import tree_sitter_rust
    import tree_sitter_c
    import tree_sitter_cpp
    import tree_sitter_c_sharp
    import tree_sitter_php
    import tree_sitter_ruby
    import tree_sitter_kotlin
    import tree_sitter_swift
    import tree_sitter_lua
    import tree_sitterPerl
    import tree_sitter_dart
    import tree_sitter_scala
    import tree_sitter_solidity
    TREE_SITTER_LANGS_AVAILABLE = True
except ImportError:
    TREE_SITTER_LANGS_AVAILABLE = False


@dataclass
class TSNode:
    """Wrapper for a tree-sitter node with metadata."""
    type: str
    start_line: int
    end_line: int
    start_col: int
    end_col: int
    text: str
    children: List['TSNode'] = field(default_factory=list)
    parent: Optional['TSNode'] = None


@dataclass
class ParseResult:
    """Result of parsing a source file."""
    language: str
    filepath: str
    tree: Optional[object] = None
    root: Optional[TSNode] = None
    errors: List[str] = field(default_factory=list)
    success: bool = False


# Map file extensions to tree-sitter language names
EXTENSION_LANGUAGE_MAP = {
    '.py': 'python',
    '.js': 'javascript',
    '.jsx': 'javascript',
    '.mjs': 'javascript',
    '.ts': 'typescript',
    '.tsx': 'typescript',
    '.java': 'java',
    '.go': 'go',
    '.rs': 'rust',
    '.c': 'c',
    '.h': 'c',
    '.cpp': 'cpp',
    '.hpp': 'cpp',
    '.cc': 'cpp',
    '.cxx': 'cpp',
    '.cs': 'c_sharp',
    '.php': 'php',
    '.rb': 'ruby',
    '.kt': 'kotlin',
    '.kts': 'kotlin',
    '.swift': 'swift',
    '.lua': 'lua',
    '.pl': 'perl',
    '.pm': 'perl',
    '.dart': 'dart',
    '.scala': 'scala',
    '.sol': 'solidity',
}

# Display names for languages
LANGUAGE_DISPLAY_NAMES = {
    'python': 'Python',
    'javascript': 'JavaScript',
    'typescript': 'TypeScript',
    'java': 'Java',
    'go': 'Go',
    'rust': 'Rust',
    'c': 'C',
    'cpp': 'C++',
    'c_sharp': 'C#',
    'php': 'PHP',
    'ruby': 'Ruby',
    'kotlin': 'Kotlin',
    'swift': 'Swift',
    'lua': 'Lua',
    'perl': 'Perl',
    'dart': 'Dart',
    'scala': 'Scala',
    'solidity': 'Solidity',
}


class TreeSitterParser:
    """Multi-language parser using Tree-sitter for unified CST parsing."""

    def __init__(self):
        self._parsers: Dict[str, Parser] = {}
        self._languages: Dict[str, Language] = {}
        self._available = TREE_SITTER_AVAILABLE and TREE_SITTER_LANGS_AVAILABLE
        if self._available:
            self._init_languages()

    def _init_languages(self):
        """Initialize tree-sitter language objects."""
        lang_modules = {
            'python': tree_sitter_python,
            'javascript': tree_sitter_javascript,
            'typescript': tree_sitter_typescript,
            'java': tree_sitter_java,
            'go': tree_sitter_go,
            'rust': tree_sitter_rust,
            'c': tree_sitter_c,
            'cpp': tree_sitter_cpp,
            'c_sharp': tree_sitter_c_sharp,
            'php': tree_sitter_php,
            'ruby': tree_sitter_ruby,
            'kotlin': tree_sitter_kotlin,
            'swift': tree_sitter_swift,
            'lua': tree_sitter_lua,
            'perl': tree_sitterPerl,
            'dart': tree_sitter_dart,
            'scala': tree_sitter_scala,
            'solidity': tree_sitter_solidity,
        }

        for lang_name, module in lang_modules.items():
            try:
                lang_obj = Language(module.language())
                parser = Parser(lang_obj)
                self._languages[lang_name] = lang_obj
                self._parsers[lang_name] = parser
            except Exception:
                pass

    @property
    def available(self) -> bool:
        return self._available

    @property
    def supported_languages(self) -> List[str]:
        return list(self._parsers.keys())

    def get_language(self, filepath: str) -> Optional[str]:
        """Get the tree-sitter language name for a file extension."""
        ext = os.path.splitext(filepath)[1].lower()
        return EXTENSION_LANGUAGE_MAP.get(ext)

    def can_parse(self, filepath: str) -> bool:
        """Check if we can parse this file."""
        lang = self.get_language(filepath)
        return lang is not None and lang in self._parsers

    def parse_file(self, filepath: str, content: Optional[str] = None) -> ParseResult:
        """Parse a source file and return a ParseResult with CST."""
        lang_name = self.get_language(filepath)
        if not lang_name or lang_name not in self._parsers:
            return ParseResult(
                language=lang_name or 'unknown',
                filepath=filepath,
                errors=[f"No parser available for language: {lang_name}"]
            )

        if content is None:
            try:
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
            except (OSError, PermissionError) as e:
                return ParseResult(
                    language=lang_name,
                    filepath=filepath,
                    errors=[str(e)]
                )

        if not content:
            return ParseResult(
                language=lang_name,
                filepath=filepath,
                errors=["Empty file"]
            )

        try:
            parser = self._parsers[lang_name]
            tree = parser.parse(content.encode('utf-8'))
            root = self._convert_node(tree.root_node, content)
            return ParseResult(
                language=lang_name,
                filepath=filepath,
                tree=tree,
                root=root,
                success=True
            )
        except Exception as e:
            return ParseResult(
                language=lang_name,
                filepath=filepath,
                errors=[str(e)]
            )

    def parse_source(self, source: str, language: str) -> ParseResult:
        """Parse source code string directly."""
        if language not in self._parsers:
            return ParseResult(
                language=language,
                filepath="<string>",
                errors=[f"No parser for: {language}"]
            )

        if not source:
            return ParseResult(
                language=language,
                filepath="<string>",
                errors=["Empty source"]
            )

        try:
            parser = self._parsers[language]
            tree = parser.parse(source.encode('utf-8'))
            root = self._convert_node(tree.root_node, source)
            return ParseResult(
                language=language,
                filepath="<string>",
                tree=tree,
                root=root,
                success=True
            )
        except Exception as e:
            return ParseResult(
                language=language,
                filepath="<string>",
                errors=[str(e)]
            )

    def _convert_node(self, node, source: str) -> TSNode:
        """Recursively convert a tree-sitter node to our TSNode wrapper."""
        text = ""
        try:
            text = source[node.start_byte:node.end_byte]
        except Exception:
            pass

        ts_node = TSNode(
            type=node.type,
            start_line=node.start_point[0],
            end_line=node.end_point[0],
            start_col=node.start_point[1],
            end_col=node.end_point[1],
            text=text,
        )

        children = []
        for child in node.children:
            child_ts = self._convert_node(child, source)
            child_ts.parent = ts_node
            children.append(child_ts)
        ts_node.children = children

        return ts_node

    def find_nodes_by_type(self, root: TSNode, node_type: str) -> List[TSNode]:
        """Find all nodes of a given type in the CST."""
        results = []
        if root.type == node_type:
            results.append(root)
        for child in root.children:
            results.extend(self.find_nodes_by_type(child, node_type))
        return results

    def find_function_definitions(self, root: TSNode) -> List[TSNode]:
        """Find all function/method definitions."""
        func_types = {
            'function_definition', 'function_declaration',
            'method_definition', 'method_declaration',
            'arrow_function', 'function',
            'constructor_declaration',
            'generator_function_declaration',
            'func_literal',  # Go
            'function_item',  # Rust
            'method_declaration',
        }
        results = []
        for child in root.children:
            if child.type in func_types:
                results.append(child)
            results.extend(self.find_function_definitions(child))
        return results

    def find_class_definitions(self, root: TSNode) -> List[TSNode]:
        """Find all class/type definitions."""
        class_types = {
            'class_definition', 'class_declaration',
            'interface_declaration', 'type_declaration',
            'struct_declaration', 'enum_declaration',
            'trait_declaration', 'impl_item',
        }
        results = []
        for child in root.children:
            if child.type in class_types:
                results.append(child)
            results.extend(self.find_class_definitions(child))
        return results

    def find_string_concatenation(self, root: TSNode) -> List[TSNode]:
        """Find string concatenation nodes (potential injection points)."""
        concat_types = {
            'concatenated_string', 'binary_operator',
            'template_string', 'f_string',
            'interpolated_string',
        }
        results = []
        for child in root.children:
            if child.type in concat_types:
                if any(op in child.text for op in ['+', '%', 'f"', 'f\'']):
                    results.append(child)
            results.extend(self.find_string_concatenation(child))
        return results

    def get安全保障分析(self, root: TSNode) -> Dict:
        """Extract security-relevant information from CST."""
        return {
            'functions': len(self.find_function_definitions(root)),
            'classes': len(self.find_class_definitions(root)),
            'string_concats': len(self.find_string_concatenation(root)),
            'dangerous_calls': self._find_dangerous_calls(root),
        }

    def _find_dangerous_calls(self, root: TSNode) -> List[TSNode]:
        """Find potentially dangerous function calls."""
        dangerous_names = {
            'eval', 'exec', 'system', 'popen', 'subprocess',
            'os.system', 'os.popen', 'shell_exec', 'passthru',
            'Runtime.exec', 'ProcessBuilder', 'child_process',
            'dangerouslySetInnerHTML', 'innerHTML', 'document.write',
            'pickle.load', 'yaml.load', 'marshal.load',
            'deserializ', 'unserialize', 'marshal.loads',
            'format', 'printf', 'sprintf',
        }
        results = []
        for child in root.children:
            if child.type == 'call':
                func_name = child.children[0].text if child.children else ''
                if any(d in func_name for d in dangerous_names):
                    results.append(child)
            results.extend(self._find_dangerous_calls(child))
        return results


# Global singleton
_parser_instance: Optional[TreeSitterParser] = None


def get_parser() -> TreeSitterParser:
    """Get or create the global Tree-sitter parser instance."""
    global _parser_instance
    if _parser_instance is None:
        _parser_instance = TreeSitterParser()
    return _parser_instance


def is_tree_sitter_available() -> bool:
    """Check if tree-sitter is available."""
    return TREE_SITTER_AVAILABLE and TREE_SITTER_LANGS_AVAILABLE
