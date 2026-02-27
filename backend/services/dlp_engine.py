import re
import PyPDF2
from docx import Document
import io

class DLPEngine:
    def __init__(self):
        self.patterns = {
            "Credit Card": r"\b(?:\d[ -]*?){13,16}\b",
            "Aadhaar": r"\b\d{4}\s\d{4}\s\d{4}\b",
            "PAN Card": r"\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b",
            "API Key": r"(?:sk_live_|AIza)[0-9a-zA-Z_-]{20,}",
            "Email Address": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
            "Phone Number": r"\b(?:\+?\d{1,3}[- ]?)?\(?\d{3}\)?[- ]?\d{3}[- ]?\d{4}\b",
            "Password String": r"(?i)(?:password|passwd|pwd)\s*[:=]\s*['\"]?[\w!@#$%^&*()]+['\"]?"
        }

    def scan_text(self, text):
        detected_counts = {}
        for label, pattern in self.patterns.items():
            matches = re.findall(pattern, text)
            if matches:
                detected_counts[label] = len(matches)
        return detected_counts

    def extract_text(self, file_stream, filename):
        text = ""
        filename = filename.lower()
        if filename.endswith('.txt'):
            text = file_stream.read().decode('utf-8', errors='ignore')
        elif filename.endswith('.pdf'):
            reader = PyPDF2.PdfReader(file_stream)
            for page in reader.pages:
                text += page.extract_text()
        elif filename.endswith(('.doc', '.docx')):
            doc = Document(file_stream)
            for para in doc.paragraphs:
                text += para.text + "\n"
        return text

    def scan_file(self, file_stream, filename):
        text = self.extract_text(file_stream, filename)
        return self.scan_text(text)
