import re
import tkinter as tk
from tkinter import filedialog, scrolledtext
from PyPDF2 import PdfReader

# Regex to detect either color/invisible commands or text-showing operations
TOKEN_RE = re.compile(
    rb"(?:\d+\s+\d+\s+\d+\s+(?:rg|RG)|\d+\s+g|\d+\s+G|Tr\s+3)"
    rb"|\[\s*(?:\([^)]*\)\s*)+\]\s*TJ"
    rb"|\(.*?\)\s*Tj",
    re.DOTALL
)
# Define normal (black) drawing commands
NORMAL_BLACK = {b"0 0 0 rg", b"0 g", b"0 0 0 RG", b"0 G"}


def extract_captures(raw_bytes):
    """
    From a raw PDF content byte string, identify runs of text
    drawn in non-black or invisible mode by scanning tokens.
    """
    captures = []
    buffer = []
    capturing = False

    for m in TOKEN_RE.finditer(raw_bytes):
        token = m.group(0).strip()
        # Color/invisible commands
        if re.match(rb"^\d+\s+\d+\s+\d+\s+(?:rg|RG)$", token) or \
           re.match(rb"^\d+\s+g$", token) or \
           re.match(rb"^\d+\s+G$", token) or \
           token.startswith(b"Tr 3"):
            # If normal black, stop capturing
            if token in NORMAL_BLACK:
                if capturing:
                    captures.append(''.join(buffer))
                    buffer.clear()
                    capturing = False
            else:
                capturing = True
            continue

        # While capturing, collect text
        if capturing:
            if token.endswith(b"TJ"):
                # Array of literals
                parts = re.findall(rb"\((.*?)\)", token, re.DOTALL)
                text = ''.join(p.decode('utf-8', errors='replace') for p in parts)
                buffer.append(text)
            elif token.endswith(b"Tj"):
                # Single string literal
                inner = re.search(rb"\((.*?)\)", token, re.DOTALL)
                if inner:
                    buffer.append(inner.group(1).decode('utf-8', errors='replace'))

    # Flush at end if still capturing
    if capturing and buffer:
        captures.append(''.join(buffer))

    return captures


def scan_pdf(path):
    """
    Scan the given PDF for runs of text drawn with abnormal colors or invisible mode.
    Returns a dict mapping page numbers to lists of captured text runs.
    """
    reader = PdfReader(path)
    results = {}

    for page_num, page in enumerate(reader.pages, start=1):
        contents = page.get_contents()
        if not contents:
            continue
        # Aggregate raw content bytes
        raw = b""
        streams = contents if isinstance(contents, list) else [contents]
        for stream in streams:
            try:
                raw += stream.get_data()
            except:
                pass

        runs = extract_captures(raw)
        if runs:
            results[page_num] = runs

    return results


class PDFHiddenTextDetectorApp(tk.Tk):
    """
    GUI for detecting hidden or abnormal-color text runs in PDF files.
    """
    def __init__(self):
        super().__init__()
        self.title("PDF Hidden Text Detector")
        self.geometry("800x600")
        self.filepath = None

        tk.Label(self, text="Select a PDF to scan for hidden/abnormal-color text:").pack(pady=10)
        tk.Button(self, text="Select PDF", command=self.select_file).pack(pady=5)
        self.scan_btn = tk.Button(self, text="Scan PDF", command=self.scan_file, state=tk.DISABLED)
        self.scan_btn.pack(pady=5)

        self.result_area = scrolledtext.ScrolledText(self, wrap=tk.WORD)
        self.result_area.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    def select_file(self):
        file = filedialog.askopenfilename(filetypes=[("PDF files", "*.pdf")])
        if file:
            self.filepath = file
            self.scan_btn.config(state=tk.NORMAL)
            self.result_area.delete(1.0, tk.END)
            self.result_area.insert(tk.END, f"Selected file: {file}\n")

    def scan_file(self):
        self.result_area.delete(1.0, tk.END)
        if not self.filepath:
            return
        results = scan_pdf(self.filepath)
        if not results:
            self.result_area.insert(tk.END, "✓ No hidden or abnormal-color text runs found.\n")
        else:
            for page, runs in results.items():
                self.result_area.insert(tk.END, f"Page {page}:\n")
                for i, run in enumerate(runs, start=1):
                    self.result_area.insert(tk.END, f"  Run {i}: {run}\n")
                self.result_area.insert(tk.END, "\n")


if __name__ == "__main__":
    app = PDFHiddenTextDetectorApp()
    app.mainloop()

# Requirements:
# pip install PyPDF2