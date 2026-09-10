from typing import List

# Extensions where # starts a line comment
HASH_COMMENT_EXTS = {
    '.py', '.rb', '.sh', '.yaml', '.yml', '.toml', '.ini', '.cfg', '.conf',
    '.properties', '.dockerfile', '.r', '.ps1', '.bat', '.php', '.pl', '.pm',
    '.groovy',
}

# Extensions where // starts a line comment
SLASH_COMMENT_EXTS = {
    '.js', '.ts', '.jsx', '.tsx', '.java', '.go', '.c', '.cpp', '.h', '.hpp',
    '.cs', '.rs', '.swift', '.kt', '.scala', '.dart', '.groovy', '.sql', '.lua',
    '.css', '.scss',
}

# Extensions supporting /* */ block comments
BLOCK_COMMENT_EXTS = SLASH_COMMENT_EXTS - {'.lua'} | {'.php', '.css', '.scss'}

# Extensions with template literals (backtick strings)
BACKTICK_EXTS = {'.js', '.ts', '.jsx', '.tsx'}


def _is_hash_comment(ext: str) -> bool:
    return ext in HASH_COMMENT_EXTS


def _is_slash_comment(ext: str) -> bool:
    return ext in SLASH_COMMENT_EXTS


def _is_block_comment(ext: str) -> bool:
    return ext in BLOCK_COMMENT_EXTS


def strip_comments_and_strings(content: str, ext: str) -> str:
    """Remove comments and string literals from source, preserving newlines.

    Every character that is part of a comment or a string literal is replaced
    with a space (newlines are preserved) so that line numbers and the overall
    structure of the file stay intact. Returns the sanitized content.
    """
    out = []
    i = 0
    n = len(content)
    in_block = False

    while i < n:
        c = content[i]

        if in_block:
            if c == '*' and i + 1 < n and content[i + 1] == '/':
                in_block = False
                out.append('  ')
                i += 2
                continue
            out.append(c if c == '\n' else ' ')
            i += 1
            continue

        nxt = content[i + 1] if i + 1 < n else ''

        # Line comments
        if c == '#' and _is_hash_comment(ext):
            while i < n and content[i] != '\n':
                out.append(' ')
                i += 1
            continue
        if c == '/' and nxt == '/' and _is_slash_comment(ext):
            while i < n and content[i] != '\n':
                out.append(' ')
                i += 1
            continue
        if c == '-' and nxt == '-' and ext == '.sql':
            while i < n and content[i] != '\n':
                out.append(' ')
                i += 1
            continue

        # Block comments
        if c == '/' and nxt == '*' and _is_block_comment(ext):
            in_block = True
            out.append('  ')
            i += 2
            continue

        # String literals
        if c in ('"', "'"):
            quote = c
            triple = content[i:i + 3] == quote * 3
            out.append(' ')
            i += 3 if triple else 1
            while i < n:
                if content[i] == '\\':
                    out.append('  ')
                    i += 2
                    continue
                if triple:
                    if content[i:i + 3] == quote * 3:
                        out.extend([' ', ' ', ' '])
                        i += 3
                        break
                else:
                    if content[i] == quote:
                        out.append(' ')
                        i += 1
                        break
                out.append(content[i] if content[i] == '\n' else ' ')
                i += 1
            continue

        # Template literals (JavaScript backticks)
        if c == '`' and ext in BACKTICK_EXTS:
            out.append(' ')
            i += 1
            while i < n:
                if content[i] == '\\':
                    out.append('  ')
                    i += 2
                    continue
                if content[i] == '`':
                    out.append(' ')
                    i += 1
                    break
                out.append(content[i] if content[i] == '\n' else ' ')
                i += 1
            continue

        out.append(c)
        i += 1

    return ''.join(out)


def get_code_indices(lines: List[str], extension: str) -> List[int]:
    """Return indices of lines that are not pure comments.

    Kept for backwards compatibility; full-content stripping is preferred.
    """
    in_block_comment = False
    code_lines = []

    for i, line in enumerate(lines):
        stripped = line.strip()

        if in_block_comment:
            if _is_block_comment(extension) and '*/' in stripped:
                in_block_comment = False
                if stripped.endswith('*/') and not stripped.startswith('*'):
                    code_lines.append(i)
            continue

        if not stripped:
            code_lines.append(i)
            continue

        if _is_hash_comment(extension) and stripped.startswith('#') and extension != '.groovy':
            continue
        if extension == '.groovy' and stripped.startswith(('#', '//')):
            continue

        if _is_slash_comment(extension) and stripped.startswith('//'):
            continue

        if _is_block_comment(extension) and stripped.startswith('/*'):
            if '*/' not in stripped[2:] or stripped.count('/*') > stripped.count('*/'):
                in_block_comment = True
            continue

        code_lines.append(i)

    return code_lines