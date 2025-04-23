import argparse
import re
from pathlib import Path
import logging
import mmap
import sys
from typing import List, Union, BinaryIO

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('keyword_search.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def find_keyword_in_file(file_path: Union[str, Path], 
                         keyword: str, 
                         binary_mode: bool = False,
                         context_lines: int = 0) -> List[str]:
    """
    Search for all occurrences of the keyword in a file (text or binary)
    
    Args:
        file_path: Path to the input file
        keyword: Keyword to search for
        binary_mode: Whether to search in binary mode
        context_lines: Number of surrounding lines to include (text mode only)
    
    Returns:
        List of matching strings with optional context
    """
    matches = []
    try:
        if binary_mode:
            # Binary search using mmap for large files
            with open(file_path, 'rb') as file:
                with mmap.mmap(file.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                    pattern = re.compile(re.escape(keyword.encode()), re.IGNORECASE)
                    for match in pattern.finditer(mm):
                        start = max(0, match.start() - 20)
                        end = min(len(mm), match.end() + 20)
                        context = mm[start:end].decode('ascii', errors='replace')
                        matches.append(f"Offset 0x{match.start():X}: {context}")
                        logger.debug(f"Binary match at 0x{match.start():X}")
        else:
            # Text search with context
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
                buffer = []
                pattern = re.compile(re.escape(keyword), re.IGNORECASE)
                
                for line_num, line in enumerate(file, 1):
                    if pattern.search(line):
                        logger.debug(f"Match found at line {line_num}")
                        if context_lines > 0:
                            # Add surrounding context
                            start_line = max(1, line_num - context_lines)
                            end_line = line_num + context_lines
                            context = f"Lines {start_line}-{end_line}:\n"
                            buffer = buffer[-(context_lines*2):]  # Keep only needed context
                            buffer.append(line)
                            context += ''.join(buffer)
                            matches.append(context)
                            buffer = []
                        else:
                            matches.append(f"Line {line_num}: {line.strip()}")
                    elif context_lines > 0:
                        buffer.append(line)
                        if len(buffer) > context_lines * 2:
                            buffer.pop(0)
    
    except Exception as e:
        logger.error(f"Error processing file: {str(e)}", exc_info=True)
        return []
    
    return matches

def main():
    parser = argparse.ArgumentParser(
        description='Advanced keyword search tool for files',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument('-f', '--file', required=True, 
                       help='Input file path')
    parser.add_argument('-k', '--keyword', required=True,
                       help='Keyword to search for')
    parser.add_argument('-b', '--binary', action='store_true',
                       help='Search in binary mode')
    parser.add_argument('-c', '--context', type=int, default=0,
                       help='Number of context lines to show around matches')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Enable verbose debug output')
    parser.add_argument('-o', '--output',
                       help='Output file for results')
    
    args = parser.parse_args()

    if args.verbose:
        logger.setLevel(logging.DEBUG)
        logger.debug("Verbose debug logging enabled")

    # Validate input file
    file_path = Path(args.file)
    if not file_path.is_file():
        logger.error(f"File not found: {file_path}")
        sys.exit(1)

    logger.info(f"Searching for '{args.keyword}' in {file_path} "
               f"(mode: {'binary' if args.binary else 'text'})")

    results = find_keyword_in_file(
        file_path, 
        args.keyword,
        binary_mode=args.binary,
        context_lines=args.context
    )
    
    # Output results
    if results:
        summary = f"Found {len(results)} matches for '{args.keyword}'"
        logger.info(summary)
        
        if args.output:
            with open(args.output, 'w', encoding='utf-8') as out_file:
                out_file.write(summary + "\n\n")
                out_file.write("\n".join(results))
            logger.info(f"Results saved to {args.output}")
        
        print("\n" + summary + ":")
        for i, match in enumerate(results, 1):  # Limit to first 50 matches
            print(f"\nMatch {i}:\n{match}")
    else:
        msg = "No matches found"
        logger.info(msg)
        print(msg)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logger.info("Search interrupted by user")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", exc_info=True)
        sys.exit(1)
