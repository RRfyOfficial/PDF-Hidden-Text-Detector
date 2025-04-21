# PDF Hidden Text Detector

A Tkinter GUI tool that scans PDF files to reveal hidden, invisible, or non-black text runs, helping you uncover any concealed messages.

## Features

- **Detect Abnormal Colors:** Identifies text drawn in colors other than black (e.g., white or colored text).
- **Invisible Text Mode:** Captures text rendered with PDF's invisible text mode (Tr 3).
- **Run-Based Reporting:** Groups and displays each hidden text run per page.
- **Simple GUI:** Interactive Tkinter interface for selecting PDFs and viewing results.

## Installation

1. **Clone the repository**

   ```bash
   git clone https://github.com/yourusername/pdf-hidden-text-detector.git
   cd pdf-hidden-text-detector
   ```

2. **Install dependencies**

   ```bash
   pip install PyPDF2
   ```

## Usage

1. **Run the application**

   ```bash
   python whitespace_pdf_detector.py
   ```

2. **Select a PDF file** using the "Select PDF" button.

3. **Click "Scan PDF"** to detect hidden or abnormal-color text runs.

4. **Review results** displayed by page and run number.

## Example Output

```
Page 1:
  Run 1: thy have found me
Page 3:
  Run 1: Hehehe You found me
```

